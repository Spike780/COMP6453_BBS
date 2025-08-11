from pprint import pprint
from common.bbsp import BBSPlus
from common.elliptic_curve_config import generate_h_vector, G2_GENERATOR, FIELD_ORDER
from common.math_utils import modular_inverse
from py_ecc.optimized_bls12_381  import multiply

def test_bbs_signature1():
    # Parameters
    message_count = 3
    messages = ["10", "20", "30"]

    # Generate H vector
    H_vec = generate_h_vector(message_count)

    # Generate secret key (x) and public key (X)
    x = 12345678901234567890 % FIELD_ORDER
    X = multiply(G2_GENERATOR, x)

    # Prepare keys
    sk = (H_vec, x)
    pk = (H_vec, X)

    # Sign
    signature = BBSPlus.sign(sk, messages)
    print("Signature:", signature)

    # Verify
    valid = BBSPlus.verify(pk, messages, signature)
    print("Verification result:", valid)

    assert valid, "Signature should be valid"


def test_bbs_selective_disclosure_proof():
    # Setup
    message_count = 4
    messages = [101, 102, 103, 104]
    revealed_indices = [0, 3]  # Reveal 1nd and 4th messages

    # Generate H vector and keys
    H_vec = generate_h_vector(message_count)
    x = 44556655458246421548777 % FIELD_ORDER
    X = multiply(G2_GENERATOR, x)
    sk = (H_vec, x)
    pk = (H_vec, X)
    # Sign
    signature = BBSPlus.sign(sk, messages)
    assert BBSPlus.verify(pk, messages, signature), "Base signature should be valid"
    pprint(signature)
    # Create proof
    proof = BBSPlus.create_proof(pk, signature, messages, revealed_indices)

    # Verify proof
    result = BBSPlus.verify_proof(pk, proof)
    print("Proof verification result:", result)

    # assert result, "Selective disclosure proof should be valid"



if __name__ == "__main__":
    print("Testing signing BBS+ Signature")
    test_bbs_signature1()
    print("\n")
    print("Testing verifying BBS+ Zero Knowledge Proof")
    test_bbs_selective_disclosure_proof()
