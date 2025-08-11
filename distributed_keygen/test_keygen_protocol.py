from distributed_keygen.keygen_protocol import DistributedKeyGenerator
from common.elliptic_curve_config import G2_GENERATOR, FIELD_ORDER
from py_ecc.optimized_bls12_381 import multiply, is_inf
from distributed_keygen.shamir import evaluate_polynomial

def test_run_protocol_successful():
    print("[Test 1] Run Protocol Successful")

    n, t = 5, 3
    dkg = DistributedKeyGenerator(n=n, t=t, field_order=FIELD_ORDER, curve_generator=G2_GENERATOR)
    private_shares, master_public_key = dkg.run_protocol()

    assert isinstance(private_shares, dict), "private_shares should be a dict"
    assert len(private_shares) == n, f"Expected {n} private shares"
    assert isinstance(master_public_key, tuple), "master_public_key should be a tuple"

    for server_id, share in private_shares.items():
        assert isinstance(share, int), f"Share for server {server_id} should be int"
        assert 0 <= share < FIELD_ORDER, f"Share {share} out of bounds"

    assert not is_inf(master_public_key), "Public key should not be at infinity"
    print("✓ [Test 1] Passed")


def test_invalid_t_n_values():
    print("[Test 2] Invalid t > n Should Raise ValueError")
    n, t = 3, 4
    try:
        DistributedKeyGenerator(n=n, t=t, field_order=FIELD_ORDER, curve_generator=G2_GENERATOR)
        raise AssertionError("Expected ValueError when t > n")
    except ValueError:
        print("✓ [Test 2] Passed")


def test_consistency_check_failure():
    print("[Test 3] Consistency Check Failure")

    n, t = 5, 3
    dkg = DistributedKeyGenerator(n=n, t=t, field_order=FIELD_ORDER, curve_generator=G2_GENERATOR)

    # Forge polynomials
    dkg._DistributedKeyGenerator__server_polynomials = {
        i: [10 * i, 20 * i, 30 * i] for i in range(1, n + 1)
    }

    # Reconstruct valid public shares

    p_star_i = {
        i: sum(
            evaluate_polynomial(poly, i, FIELD_ORDER)
            for poly in dkg._DistributedKeyGenerator__server_polynomials.values()
        ) % FIELD_ORDER
        for i in range(1, n + 1)
    }

    public_shares = {i: multiply(G2_GENERATOR, val) for i, val in p_star_i.items()}

    # Tamper one share
    public_shares[n] = multiply(G2_GENERATOR, 12345)

    try:
        dkg._perform_consistency_check(public_shares)
        raise AssertionError("Expected ValueError due to tampered share")
    except ValueError:
        print("✓ [Test 3] Passed")

if __name__ == "__main__":
    test_run_protocol_successful()
    test_invalid_t_n_values()
    test_consistency_check_failure()
