from dataclasses import dataclass
from common.elliptic_curve_config import G1_INFINITY, FIELD_ORDER
from common.math_utils import modular_inverse
from py_ecc.optimized_bls12_381 import add, multiply



@dataclass
class SignatureShare:
    """
    Defines a data structure for signature fragments received from the server.
    """
    server_id: int
    e: int
    s: int
    R_i: object
    u_i: int

@dataclass
class FinalSignature:
    """
    Define the final BBS+ signature.
    """
    A: object
    e: int
    s: int


def reconstruct_signature(shares: list[SignatureShare], field_order: int, g1_generator) -> FinalSignature:
    """
    Reconstruct the signature fragments into a complete BBS+ signature.
    """

    ref_e = shares[0].e
    ref_s = shares[0].s

    # Check for remaining debris
    for share in shares[1:]:
        if share.e != ref_e or share.s != ref_s:
            raise ValueError(
                f"Signature fragments are inconsistent! Server {shares[0].server_id}"
                f"(e={ref_e}, s={ref_s}) with server {share.server_id} "
                f"The values of (e={share.e}, s={share.s}) are different."
            )
    # print("Correct")

    # Starting from the zero element (infinity) of the G1 group
    R_sum = G1_INFINITY
    for share in shares:
        R_sum = add(R_sum, share.R_i)
    
    # calculate u_sum = Σ u_i
    u_sum = 0
    for share in shares:
        u_sum += share.u_i
    u_sum %= FIELD_ORDER


    if u_sum == 0:
        raise ValueError("The sum of u_i is 0, and the modular inverse cannot be calculated.")

    # Compute the modular inverse of u_sum
    u_sum_inv = modular_inverse(u_sum, FIELD_ORDER)
    
    # Scalar multiplication of points
    A = multiply(R_sum, u_sum_inv)

    return FinalSignature(A=A, e=ref_e, s=ref_s)