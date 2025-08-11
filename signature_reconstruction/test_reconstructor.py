import secrets
from py_ecc.optimized_bls12_381 import add, multiply, normalize
from signature_reconstruction.reconstructor import reconstruct_signature, SignatureShare
from common.elliptic_curve_config import FIELD_ORDER, G1_GENERATOR, G1_INFINITY
from common.math_utils import modular_inverse

def test_reconstruction_successful():
    """
    Test scenario: Simulate t servers returning consistent, valid signature fragments and verify that they can be successfully reconstructed.
    This simulates the successful path of step 12 of the protocol.
    """
    print("[Test 1] Testing successful signature reconstruction")
    
    # --- 1. Setup and simulation ---
    num_shares = 3
    common_e = secrets.randbelow(FIELD_ORDER)
    common_s = secrets.randbelow(FIELD_ORDER)

    shares = []
    u_values = [secrets.randbelow(FIELD_ORDER) for _ in range(num_shares)]
    R_points = [multiply(G1_GENERATOR, secrets.randbelow(FIELD_ORDER)) for _ in range(num_shares)]

    for i in range(num_shares):
        share = SignatureShare(
            server_id=i + 1,
            e=common_e,
            s=common_s,
            R_i=R_points[i],
            u_i=u_values[i]
        )
        shares.append(share)

    # --- 2. Calculate expected results ---
    R_sum = G1_INFINITY
    for p in R_points:
        R_sum = add(R_sum, p)

    u_sum = sum(u_values) % FIELD_ORDER
    if u_sum == 0:
        u_values[0] = (u_values[0] + 1) % FIELD_ORDER
        u_sum = sum(u_values) % FIELD_ORDER

    u_sum_inv = modular_inverse(u_sum, FIELD_ORDER)
    expected_A = multiply(R_sum, u_sum_inv)

    # --- 3. Perform refactoring and verify ---
    final_signature = reconstruct_signature(shares, FIELD_ORDER, G1_GENERATOR)

    assert normalize(final_signature.A) == normalize(expected_A), "Reconstructed point A is incorrect"
    assert final_signature.e == common_e, "Reconstructed e value is incorrect"
    assert final_signature.s == common_s, "Reconstructed s value is incorrect"
    print("✓ [Test 1] Passed")


def test_reconstruction_fails_with_inconsistent_e():
    """
    Test scenario: simulate a server returning a different e value than other servers.
    """
    print("[Test 2] Testing reconstruction failure due to inconsistent 'e'")
    shares = [
        SignatureShare(server_id=1, e=100, s=200, R_i=G1_GENERATOR, u_i=50),
        SignatureShare(server_id=2, e=999, s=200, R_i=G1_GENERATOR, u_i=60) # diff e
    ]

    try:
        reconstruct_signature(shares, FIELD_ORDER, G1_GENERATOR)
        raise AssertionError("Expected ValueError for inconsistent 'e', but none was raised.")
    except ValueError as e:
        assert "Signature fragments are inconsistent!" in str(e)
        print("✓ [Test 2] Passed")


def test_reconstruction_fails_with_inconsistent_s():
    """
    Test scenario: simulate a server returning a different s value than other servers.
    """
    print("[Test 3] Testing reconstruction failure due to inconsistent 's'")
    shares = [
        SignatureShare(server_id=1, e=100, s=200, R_i=G1_GENERATOR, u_i=50),
        SignatureShare(server_id=2, e=100, s=999, R_i=G1_GENERATOR, u_i=60) # s different
    ]

    try:
        reconstruct_signature(shares, FIELD_ORDER, G1_GENERATOR)
        raise AssertionError("Expected ValueError for inconsistent 's', but none was raised.")
    except ValueError as e:
        assert "Signature fragments are inconsistent!" in str(e)
        print("✓ [Test 3] Passed")


def test_reconstruction_fails_with_zero_u_sum():
    """
    Test scenario: The sum of all u_i is 0 over a finite field, making it impossible to calculate the modular inverse.
    """
    print("[Test 4] Testing reconstruction failure due to u_sum being zero")
    u1 = 50
    u2 = FIELD_ORDER - 50  # u1 + u2 = 0 (mod FIELD_ORDER)
    
    shares = [
        SignatureShare(server_id=1, e=100, s=200, R_i=G1_GENERATOR, u_i=u1),
        SignatureShare(server_id=2, e=100, s=200, R_i=G1_GENERATOR, u_i=u2)
    ]
    
    try:
        reconstruct_signature(shares, FIELD_ORDER, G1_GENERATOR)
        raise AssertionError("Expected ValueError for zero u_sum, but none was raised.")
    except ValueError as e:
        assert "The sum of u_i is 0" in str(e)
        print("✓ [Test 4] Passed")


if __name__ == "__main__":
    test_reconstruction_successful()
    print("-" * 20)
    test_reconstruction_fails_with_inconsistent_e()
    print("-" * 20)
    test_reconstruction_fails_with_inconsistent_s()
    print("-" * 20)
    test_reconstruction_fails_with_zero_u_sum()