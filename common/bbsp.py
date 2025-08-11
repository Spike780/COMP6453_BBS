import os
import hashlib
from typing import Dict, List, Tuple
from common.elliptic_curve_config import G1_GENERATOR, G2_GENERATOR, FIELD_ORDER, generate_h_vector
from common.math_utils import modular_inverse
from py_ecc.optimized_bls12_381 import add, multiply, pairing
from secrets import randbelow
from py_ecc.optimized_bls12_381.optimized_curve import is_inf, is_on_curve, normalize

PointG1 = Tuple[int, int, int]  # Representation of a point in G1
PointG2 = Tuple[int, int, int]  # Representation of a point in G2

# BBS+ Version 7, ZK Proof double commitment
# Implemented based on MATTR Rust Implementation

class BBSPlus:
    @staticmethod
    def sign(sk: Tuple[List[PointG1], int], messages: List[int]) -> Tuple[PointG1, int, int]:
        """
        Create a BBS+ signature on a list of messages.

        Args:
            sk: A tuple (H_vector, x) where H_vector is a list of G1 points H[0..ℓ]
                and x is the secret key scalar.
            messages: A list of ℓ integers (each modulo FIELD_ORDER).

        Returns:
            A tuple (A, e, s) representing the signature.
        """
        H, x = sk
        l = len(messages)
        # Sample random nonces
        e = randbelow(FIELD_ORDER)
        s = randbelow(FIELD_ORDER)

        # Build numerator: G1 + s*H[0] + sum_i m_i * H[i+1]
        numerator = G1_GENERATOR
        numerator = add(numerator, multiply(H[0], s))
        for i, m in enumerate(messages):
            numerator = add(numerator, multiply(H[i+1], m))

        # Compute A = numerator * (x + e)^{-1}
        denom_inv = modular_inverse((x + e) % FIELD_ORDER, FIELD_ORDER)
        A = multiply(numerator, denom_inv)
        return A, e, s

    @staticmethod
    def verify(pk: Tuple[List[PointG1], PointG2], messages: List[int], signature: Tuple[PointG1, int, int]) -> bool:
        """
        Verify a BBS+ signature.

        Args:
            pk: A tuple (H_vector, X) where H_vector is a list of G1 points H[0..ℓ]
                and X is the public key point in G2.
            messages: A list of ℓ integers (each modulo FIELD_ORDER).
            signature: A tuple (A, e, s).

        Returns:
            True if valid, False otherwise.
        """
        H, X = pk
        A, e, s = signature

        # Reconstruct the commitment
        RHS = G1_GENERATOR
        RHS = add(RHS, multiply(H[0], s))
        for i, m in enumerate(messages):
            RHS = add(RHS, multiply(H[i+1], m))
        
        # Check pairing equation
        
        lhs = pairing(add(X, multiply(G2_GENERATOR, e)), A)
        rhs = pairing(G2_GENERATOR, RHS)
        return lhs == rhs

    @staticmethod
    def create_proof(pk: Tuple[List[PointG1], PointG2],
                     signature: Tuple[PointG1, int, int],
                     messages: List[int],
                     revealed_indices: List[int],
                     nonce: bytes = b"default_nonce") -> Dict:
        H, X = pk
        A, e, s = signature
        l = len(messages)

        # rebuild B
        B = G1_GENERATOR
        B = add(B, multiply(H[0], s))
        for i, m in enumerate(messages):
            B = add(B, multiply(H[i+1], m))

        # randomize signature with two scalars
        r1 = randbelow(FIELD_ORDER)
        r2 = randbelow(FIELD_ORDER)
        A_bar = multiply(A, (r1 * r2) % FIELD_ORDER)
        D = multiply(B, r2)

        B_bar = add(
            multiply(D, r1),
            multiply(A_bar, e)
        )

        # separate revealed vs hidden
        revealed_set = set(revealed_indices)
        hidden = [i for i in range(ℓ) if i not in revealed_set]

        # sample randomness
        e_t = randbelow(FIELD_ORDER)
        r1_t = randbelow(FIELD_ORDER)
        r3_t = randbelow(FIELD_ORDER)
        m_t = {j: randbelow(FIELD_ORDER) for j in hidden}

        #commitments
        T1 = add(multiply(A_bar, e_t), multiply(D, r1_t))
        hidden_commit = None
        
        for j in hidden:
            term = multiply(H[j+1], m_t[j])
            hidden_commit = term if hidden_commit is None else add(hidden_commit, term)
        if hidden_commit is None:
            from py_ecc.optimized_bls12_381.optimized_curve import Z1 as G1_ID
            hidden_commit = G1_ID
            
        T2 = add(multiply(H[0], r3_t), hidden_commit)
        

        # Fiat-Shamir
        def ser(P: PointG1) -> bytes:
            x, y = normalize(P)
            return x.n.to_bytes(48, 'big') + y.n.to_bytes(48, 'big')

        hash_input = b''.join([ser(A_bar), ser(B_bar), ser(D), ser(T1), ser(T2), nonce])
        c = int.from_bytes(hashlib.sha256(hash_input).digest(), 'big') % FIELD_ORDER

        # responses
        resp_e = (e_t + c * e) % FIELD_ORDER
        resp_r1 = (r1_t + c * r1) % FIELD_ORDER
        resp_r3 = (r3_t + c * s) % FIELD_ORDER
        resp_m = {j: (m_t[j] + c * messages[j]) % FIELD_ORDER for j in hidden}


        return {
            'A_bar': A_bar, 'B_bar': B_bar, 'D': D,
            'T1': T1, 'T2': T2, 'c': c,
            'resp_e': resp_e, 'resp_r1': resp_r1, 'resp_r3': resp_r3,
            'resp_m': resp_m,
            'revealed': {i: messages[i] for i in revealed_indices}
        }

    def verify_proof(
        pk: Tuple[List[PointG1], PointG2],
        proof: Dict,
        nonce: bytes = b"default_nonce"
    ) -> bool:
        H, X = pk
        A_bar = proof['A_bar']
        B_bar = proof['B_bar']
        D     = proof['D']
        T1    = proof['T1']
        T2    = proof['T2']
        c     = proof['c']
        resp_e  = proof['resp_e']
        resp_r1 = proof['resp_r1']
        resp_r3 = proof['resp_r3']
        resp_m  = proof['resp_m']
        revealed = proof.get('revealed', {})

        # 1) Recompute FS challenge
        def ser(P: PointG1) -> bytes:
            x, y = normalize(P)
            return x.n.to_bytes(48, 'big') + y.n.to_bytes(48, 'big')

        h_in = b''.join([ser(A_bar), ser(B_bar), ser(D), ser(T1), ser(T2), nonce])
        if int.from_bytes(hashlib.sha256(h_in).digest(), 'big') % FIELD_ORDER != c:
            return False

        lhs1 = add(multiply(A_bar, resp_e), multiply(D, resp_r1))
        rhs1 = add(T1, multiply(B_bar, c))

        # normalize to affine coordinates
        lhs1_aff = normalize(lhs1)
        rhs1_aff = normalize(rhs1)

        if lhs1_aff != rhs1_aff:
            return False


        # 3) Check T2:  D⁽resp_r3⁾ · (∏ H[j+1]⁽resp_m[j]⁾)  ==  T2 · (∏ H[i+1]⁻ᶜ·mᵢ) for each revealed i
        lhs2 = multiply(D, resp_r3)

        # add up the hidden-message commitments
        for j, mj in resp_m.items():
            lhs2 = add(lhs2, multiply(H[j+1], mj))

        # compare in affine form
        if normalize(lhs2) != normalize(T2):
            return False

        # 4) Final pairing: verify randomized signature
        #    e.g. e(A_bar, X + resp_e·G2) == e(full_rhs, G2)
        full_rhs = G1_GENERATOR
        full_rhs = add(full_rhs, multiply(H[0], resp_r1))
        for i, mi in revealed.items():
            full_rhs = add(full_rhs, multiply(H[i+1], mi))
        for j, mj in resp_m.items():
            full_rhs = add(full_rhs, multiply(H[j+1], mj))

        lhs = pairing(A_bar, add(X, multiply(G2_GENERATOR, resp_e)))
        rhs = pairing(full_rhs, G2_GENERATOR)
        return lhs == rhs





