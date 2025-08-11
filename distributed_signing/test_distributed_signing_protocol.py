# distributed_signing/test_distributed_signing_protocol.py

from distributed_keygen.keygen_protocol import DistributedKeyGenerator
from distributed_signing.signing_protocol import DistributedSigningProtocol
from signature_reconstruction.reconstructor import reconstruct_signature
from common.bbsp import BBSPlus
from common.elliptic_curve_config import (
    FIELD_ORDER, G1_GENERATOR, G2_GENERATOR, generate_h_vector
)
from common.math_utils import interpolate_scalars
from py_ecc.optimized_bls12_381 import multiply, normalize

def test_full_signing_and_verification_flow():
    """
    Test the complete end-to-end flow from key generation to signature verification.
    """
    print("--- [Test] Starting Full End-to-End Signing & Verification Flow ---")

    # --- 1. Set parameters ---
    n = 5
    t = 3
    messages = [123, 456, 789]
    message_count = len(messages)
    print(f"Parameters: n={n}, t={t}, message_count={message_count}")

    # --- 2. Distributed Key Generation (DKG) ---
    print("\nStep 1: Running Distributed Key Generation (DKG)...")
    dkg = DistributedKeyGenerator(n=n, t=t, field_order=FIELD_ORDER, curve_generator=G2_GENERATOR)
    all_private_shares, master_public_key = dkg.run_protocol()
    print("✓ DKG complete.")

    # --- 3. Prepare the data required for signing ---
    print("\nStep 2: Preparing data for signing...")
    h_vector = generate_h_vector(message_count)
    bbs_pk = (h_vector, master_public_key)
    signing_server_ids = list(all_private_shares.keys())[:t]
    signing_servers = {server_id: all_private_shares[server_id] for server_id in signing_server_ids}
    print(f"✓ Selected {t} servers to participate in signing: {signing_server_ids}")
    
    master_secret_x = interpolate_scalars(signing_servers, 0)
    print(f"✓ Correctly interpolated master secret key x=p(0) for simulation.")

    expected_X = multiply(G2_GENERATOR, master_secret_x)
    print(f"   - Master Public Key X from DKG: {normalize(master_public_key)}")
    print(f"   - Expected X from interpolated SK: {normalize(expected_X)}")
    assert normalize(master_public_key) == normalize(expected_X), "FATAL: Master public key and secret key do not match!"
    print("✓ Master keys consistency check passed.")


    # --- 4. Execute the distributed signature protocol to generate signature fragments ---
    print("\nStep 3: Running Distributed Signing Protocol to generate shares...")
    dsp = DistributedSigningProtocol(
        signing_servers=signing_servers,
        messages=messages,
        h_vector=h_vector,
        master_secret_x=master_secret_x
    )
    signature_shares, _ = dsp.generate_shares()
    print(f"✓ Generated {len(signature_shares)} signature shares.")

    # --- 5. Reconstruct signature ---
    print("\nStep 4: Reconstructing the final signature from shares...")
    final_signature = reconstruct_signature(
        shares=signature_shares,
        field_order=FIELD_ORDER,
        g1_generator=G1_GENERATOR
    )
    print("✓ Final signature reconstructed.")
    
    # --- 6. Verify final signature ---
    print("\nStep 5: Verifying the reconstructed signature...")
    is_valid = BBSPlus.verify(
        pk=bbs_pk,
        messages=messages,
        signature=(final_signature.A, final_signature.e, final_signature.s)
    )
    print(f"✓ Verification result: {is_valid}")
    
    assert is_valid, "The final reconstructed signature failed verification!"
    print("\n--- [Test] SUCCESS: The entire flow completed successfully! ---")

if __name__ == "__main__":
    test_full_signing_and_verification_flow()