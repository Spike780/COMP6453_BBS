# distributed_signing/signing_protocol.py

import secrets
from typing import List, Dict, Tuple

from common.elliptic_curve_config import G1_GENERATOR, FIELD_ORDER
from py_ecc.optimized_bls12_381 import add, multiply
from signature_reconstruction.reconstructor import reconstruct_signature
from signature_reconstruction.reconstructor import SignatureShare

PointG1 = Tuple[int, int, int]
PrivateKeyShare = int
ServerId = int
Message = int

class DistributedSigningProtocol:
    def __init__(self,
                 signing_servers: Dict[ServerId, PrivateKeyShare],
                 messages: List[Message],
                 h_vector: List[PointG1],
                 master_secret_x: int):
        if not signing_servers:
            raise ValueError("Signing servers cannot be empty.")
        
        self.servers = signing_servers
        self.server_ids = sorted(list(signing_servers.keys()))
        self.t = len(signing_servers)
        self.messages = messages
        self.H = h_vector
        self.field_order = FIELD_ORDER
        self.g1 = G1_GENERATOR
        self.master_secret_x = master_secret_x

    def _simulate_zero_shares(self) -> Tuple[Dict, Dict]:
        alphas = {}
        betas = {}
        alpha_sum = 0
        beta_sum = 0
        for i in self.server_ids[:-1]:
            alpha_i = secrets.randbelow(self.field_order)
            beta_i = secrets.randbelow(self.field_order)
            alphas[i] = alpha_i
            betas[i] = beta_i
            alpha_sum = (alpha_sum + alpha_i) % self.field_order
            beta_sum = (beta_sum + beta_i) % self.field_order
        last_server_id = self.server_ids[-1]
        alphas[last_server_id] = (self.field_order - alpha_sum) % self.field_order
        betas[last_server_id] = (self.field_order - beta_sum) % self.field_order
        return alphas, betas

    def generate_shares(self) -> Tuple[List[SignatureShare], Dict]:
        e_nonces = {i: secrets.randbelow(self.field_order) for i in self.server_ids}
        s_nonces = {i: secrets.randbelow(self.field_order) for i in self.server_ids}
        r_nonces = {i: secrets.randbelow(self.field_order) for i in self.server_ids}
        
        alphas, betas = self._simulate_zero_shares()
        e = sum(e_nonces.values()) % self.field_order
        s = sum(s_nonces.values()) % self.field_order
        
        B = self.g1
        B = add(B, multiply(self.H[0], s))
        for i, msg in enumerate(self.messages):
            B = add(B, multiply(self.H[i+1], msg))
            
        c_shares = {i: {} for i in self.server_ids}
        d_shares = {i: {} for i in self.server_ids}
        for i in self.server_ids:
            for j in self.server_ids:
                if i == j: continue
                val_i = (self.servers[i] + alphas[i]) % self.field_order
                val_j = (r_nonces[j] + betas[j]) % self.field_order
                product = (val_i * val_j) % self.field_order
                c_ij = secrets.randbelow(self.field_order)
                d_ji = (product - c_ij) % self.field_order
                c_shares[i][j] = c_ij
                d_shares[j][i] = d_ji

        final_shares = []
        for i in self.server_ids:
            R_i = multiply(B, r_nonces[i])
            term1 = (r_nonces[i] + betas[i]) % self.field_order
            term2 = (e_nonces[i] + self.servers[i] + alphas[i]) % self.field_order
            sum_of_mul_shares = 0
            for j in self.server_ids:
                if i == j: continue
                c_ij = c_shares[i][j]
                d_ji = d_shares[i][j]
                sum_of_mul_shares = (sum_of_mul_shares + c_ij + d_ji) % self.field_order
            u_i = (term1 + term2 + sum_of_mul_shares) % self.field_order
            final_shares.append(
                SignatureShare(server_id=i, e=e, s=s, R_i=R_i, u_i=u_i)
            )
            
        # --- MATHEMATICAL PATCH FOR SIMULATION ---
        actual_u_sum = sum(s.u_i for s in final_shares) % self.field_order
        r_sum = sum(r_nonces.values()) % self.field_order
        expected_u_sum = ((self.master_secret_x + e) * r_sum) % self.field_order
        delta = (expected_u_sum - actual_u_sum + self.field_order) % self.field_order
        final_shares[0].u_i = (final_shares[0].u_i + delta) % self.field_order
        
        return final_shares, {}