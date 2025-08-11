import hashlib
from py_ecc.bls.hash_to_curve import hash_to_G1
from py_ecc.optimized_bls12_381 import G1, G2, curve_order, Z1, Z2
from py_ecc.optimized_bls12_381.optimized_curve import normalize, is_on_curve
FIELD_ORDER = curve_order

# Generation of G1
G1_GENERATOR = G1

# Generators of the G2
G2_GENERATOR = G2

# Point at infinity (identity element) of the G1 and G2 groups
G1_INFINITY = Z1
G2_INFINITY = Z2



# Global elliptic curve configuration
def generate_h_vector(length: int) -> list:
    """
    Securely generate the H vector for BBS+ signatures using IETF-standard hash_to_G1.
    
    Args:
        length (int): Number of messages (will return length + 1 elements)
        
    Returns:
        list: List of G1 points [H_0, H_1, ..., H_length]
    """
    DOMAIN_SEP = b"BBS+HGen"
    h_vector = []
    for i in range(length + 1):
        h = hash_to_G1(f"seed_for_h_{i}".encode(), DST=DOMAIN_SEP, hash_function=hashlib.sha256)
        x, y = normalize(h)
        h_vector.append((x, y, 1))
    return h_vector

# Example usage
if __name__ == "__main__":
    h_vec = generate_h_vector(5)
    for i, h in enumerate(h_vec):
        print(f"H_{i} = {h}")
