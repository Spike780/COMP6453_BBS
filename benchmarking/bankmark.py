import time
import statistics
import tracemalloc
import random
import hashlib
from distributed_keygen.keygen_protocol import DistributedKeyGenerator
from distributed_signing.signing_protocol import DistributedSigningProtocol
from signature_reconstruction.reconstructor import reconstruct_signature
from common.bbsp import BBSPlus
from common.math_utils import interpolate_scalars
from common.elliptic_curve_config import (
    FIELD_ORDER, G1_GENERATOR, G2_GENERATOR, generate_h_vector
)
from py_ecc.optimized_bls12_381 import multiply


BENCHMARK_ROUNDS = 10

def print_results_time(operation_name, times):
    if not times:
        print(f"{operation_name:<40} | No data")
        return
    avg_time = statistics.mean(times)
    min_time = min(times)
    max_time = max(times)
    print(f"{operation_name:<40} | Avg: {avg_time:.6f} s | Min: {min_time:.6f} s | Max: {max_time:.6f} s")

def print_results_memory(operation_name, memory_usages):
    if not memory_usages:
        print(f"{operation_name:<40} | No data")
        return
    avg_mem = statistics.mean(memory_usages) / 1024
    min_mem = min(memory_usages) / 1024
    max_mem = max(memory_usages) / 1024
    print(f"{operation_name:<40} | Avg Mem: {avg_mem:.2f} KB | Min Mem: {min_mem:.2f} KB | Max Mem: {max_mem:.2f} KB")

# --- Performance Benchmark Functions ---
# Simulates a client preparing messages and generating a key pair for testing
def run_client(message_count, revealed_count=0):
    messages = [random.randint(1, FIELD_ORDER-1) for _ in range(message_count)]
    h_vector = generate_h_vector(message_count)
    revealed_indices = list(range(revealed_count))
    sk = (h_vector, random.randint(1, FIELD_ORDER-1))
    pk = (h_vector, multiply(G2_GENERATOR, sk[1]))
    signature = BBSPlus.sign(sk, messages)
    
    print(f"[Client] Prepared {message_count} messages with {revealed_count} to reveal.")
    return sk, pk, messages, h_vector, revealed_indices, signature
# Simulates a server performing a cryptographic task based on a mode
def run_server(mode, measure_mode, **kwargs):
    def run_time_benchmark(op_func, op_name):
        times = []
        for _ in range(BENCHMARK_ROUNDS):
            start = time.perf_counter()
            op_func()
            end = time.perf_counter()
            times.append(end - start)
        print_results_time(op_name, times)

    def run_memory_benchmark(op_func, op_name):
        memory_usages = []
        for _ in range(BENCHMARK_ROUNDS):
            tracemalloc.start()
            op_func()
            _, peak_memory = tracemalloc.get_traced_memory()
            memory_usages.append(peak_memory)
            tracemalloc.stop()
        print_results_memory(op_name, memory_usages)

    # DKG and Signing logic
    if mode == "dkg":
        n, t = kwargs["n"], kwargs["t"]
        op_name = f"DKG (n={n}, t={t})"
        op_func = lambda: DistributedKeyGenerator(n=n, t=t, field_order=FIELD_ORDER, curve_generator=G2_GENERATOR).run_protocol()
        if measure_mode == "time":
            run_time_benchmark(op_func, op_name)
        else:
            run_memory_benchmark(op_func, op_name)
    
    elif mode == "signing":
        t = kwargs["t"]
        message_count = kwargs["message_count"]
        dkg = DistributedKeyGenerator(n=t, t=t, field_order=FIELD_ORDER, curve_generator=G2_GENERATOR)
        all_private_shares, _ = dkg.run_protocol()
        signing_servers = {sid: share for sid, share in list(all_private_shares.items())[:t]}
        master_secret_x = interpolate_scalars(signing_servers, 0)
        messages = [123] * message_count
        h_vector = generate_h_vector(message_count)
        op_name = f"Distributed Sign ({t} servers, {message_count} msgs)"
        op_func = lambda: (
            dsp := DistributedSigningProtocol(
                signing_servers=signing_servers, messages=messages,
                h_vector=h_vector, master_secret_x=master_secret_x
            ),
            shares := dsp.generate_shares(),
            reconstruct_signature(shares=shares[0], field_order=FIELD_ORDER, g1_generator=G1_GENERATOR)
        )
        if measure_mode == "time":
            run_time_benchmark(op_func, op_name)
        else:
            run_memory_benchmark(op_func, op_name)
    
    # BBS+ logic
    elif mode in ["verify", "proof_gen", "proof_verify"]:
        sk, pk, messages, h_vector, revealed_indices, signature = kwargs['client_data']
        message_count = len(messages)
        revealed_count = len(revealed_indices)
        
        if mode == "verify":
            op_name = f"BBS+ Verify ({message_count} msgs)"
            op_func = lambda: BBSPlus.verify(pk, messages, signature)
        elif mode == "proof_gen":
            op_name = f"Proof Gen ({message_count} total, {revealed_count} rev)"
            op_func = lambda: BBSPlus.create_proof(pk, signature, messages, revealed_indices)
        else: # proof_verify
            op_name = f"Proof Verify ({message_count} total, {revealed_count} rev)"
            proof = BBSPlus.create_proof(pk, signature, messages, revealed_indices)
            op_func = lambda: BBSPlus.verify_proof(pk, proof)

        if measure_mode == "time":
            run_time_benchmark(op_func, op_name)
        else:
            run_memory_benchmark(op_func, op_name)


# --- Security Test Functions ---
# Tests the unforgeability property by attempting to forge a new signatur and a modified signature
def test_unforgeability():
    print("\n--- Testing Unforgeability ---")
    try:
        # Setup, an honest party generates a key pair and signs a message
        messages = [random.randint(1, FIELD_ORDER - 1) for _ in range(5)]
        h_vector = generate_h_vector(len(messages))
        sk = (h_vector, random.randint(1, FIELD_ORDER - 1))
        pk = (h_vector, multiply(G2_GENERATOR, sk[1]))
        signature = BBSPlus.sign(sk, messages)
        print(f"  - Original signature generated.")

        # Test 1, forging a random signature on a new message
        print("  - Attempting to forge a random signature on a new message...")
        new_message = [random.randint(1, FIELD_ORDER - 1)]
        # The forged signature must have three components (A, e, s) to match the expected format
        forged_signature = (
            multiply(G1_GENERATOR, random.randint(1, FIELD_ORDER - 1)),
            random.randint(1, FIELD_ORDER - 1),
            random.randint(1, FIELD_ORDER - 1)
        )
        
        is_valid = BBSPlus.verify(pk, new_message, forged_signature)
        
        if is_valid:
            print(f"    FAILURE: Forged signature was unexpectedly valid!")
            assert False, "Forger's random signature was valid"
        else:
            print("    SUCCESS: Forged random signature was invalid as expected.")
            print(f"      > Forged Signature components (A, e, s) are invalid and cannot be verified.")
            print(f"      > Verification failed for message: {new_message[0]}")

        # Test 2, modifying an existing signature
        print("  - Attempting to modify an existing valid signature...")
        # A valid signature is a tuple of (point, scalar, scalar)
        modified_signature = (signature[0], signature[1], signature[2] + 1)
        is_valid_modified = BBSPlus.verify(pk, messages, modified_signature)
        
        if is_valid_modified:
            print(f"    FAILURE: Modified signature was unexpectedly valid!")
            assert False, "Modified signature was valid"
        else:
            print("    SUCCESS: Modified signature was invalid as expected.")
            print(f"      > The original signature has been altered and is no longer valid.")
        
        print("Unforgeability test passed.")

    except AssertionError as e:
        print(f"FAIL: {e}")
    except Exception as e:
        print(f"ERROR: An unexpected error occurred: {e}")
# Tests the unlinkability property by generating two proofs from the same signature and ensuring their outputs are distinct
def test_unlinkability():
    print("\n--- Testing Unlinkability ---")
    try:
        # Setup, generate a signature
        message_count = 50
        revealed_count = 5
        messages = [random.randint(1, FIELD_ORDER - 1) for _ in range(message_count)]
        h_vector = generate_h_vector(message_count)
        sk = (h_vector, random.randint(1, FIELD_ORDER-1))
        pk = (h_vector, multiply(G2_GENERATOR, sk[1]))
        signature = BBSPlus.sign(sk, messages)
        revealed_indices = random.sample(range(message_count), revealed_count)
        print(f"  - Generated a single signature on {message_count} messages.")

        # Test 1, generate two proofs with the SAME revealed messages
        print("  - Generating two proofs with the same revealed messages...")
        proof_A = BBSPlus.create_proof(pk, signature, messages, revealed_indices)
        proof_B = BBSPlus.create_proof(pk, signature, messages, revealed_indices)

        # Use a hash of the proofs for tangible evidence of distinctness
        proof_A_hash = hashlib.sha256(repr(proof_A).encode()).hexdigest()
        proof_B_hash = hashlib.sha256(repr(proof_B).encode()).hexdigest()

        if proof_A_hash == proof_B_hash:
            print(f"    FAILURE: Two proofs with the same input are identical!")
            print(f"      > Proof A Hash: {proof_A_hash}")
            print(f"      > Proof B Hash: {proof_B_hash}")
            assert False, "Proofs are identical, randomness is broken"
        else:
            print("    SUCCESS: Proofs with identical inputs are distinct due to randomness.")
            print(f"      > Proof A Hash (first 10 chars): {proof_A_hash[:10]}...")
            print(f"      > Proof B Hash (first 10 chars): {proof_B_hash[:10]}...")
        
        # Test 2, generate two proofs with DIFFERENT revealed messages
        print("  - Generating two proofs with different revealed messages...")
        revealed_indices_2 = random.sample([i for i in range(message_count) if i not in revealed_indices], revealed_count)
        proof_C = BBSPlus.create_proof(pk, signature, messages, revealed_indices)
        proof_D = BBSPlus.create_proof(pk, signature, messages, revealed_indices_2)
        
        proof_C_hash = hashlib.sha256(repr(proof_C).encode()).hexdigest()
        proof_D_hash = hashlib.sha256(repr(proof_D).encode()).hexdigest()

        if proof_C_hash == proof_D_hash:
            print(f"    FAILURE: Proofs with different inputs are identical!")
            print(f"      > Proof C Hash: {proof_C_hash}")
            print(f"      > Proof D Hash: {proof_D_hash}")
            assert False, "Proofs with different inputs are identical"
        else:
            print("    SUCCESS: Proofs with different inputs are distinct as expected.")
            print(f"      > Proof C Hash (first 10 chars): {proof_C_hash[:10]}...")
            print(f"      > Proof D Hash (first 10 chars): {proof_D_hash[:10]}...")

        print("Unlinkability test passed.")

    except AssertionError as e:
        print(f"FAIL: {e}")
    except Exception as e:
        print(f"ERROR: An unexpected error occurred: {e}")

def main():
    print("="*60)
    print("Running Cryptographic Protocol Benchmark Suite (Time Measurement)")
    print("Each operation is run 10 times.")
    print("="*60)
    
    # Distributed Key Generation (DKG) Time
    print("\n--- Distributed Key Generation (DKG) Time ---")
    run_server("dkg", "time", n=5, t=3)
    run_server("dkg", "time", n=10, t=5)
    run_server("dkg", "time", n=20, t=10)

    # Distributed Signing Time
    print("\n--- Distributed Signing Time ---")
    run_server("signing", "time", t=3, message_count=10)
    run_server("signing", "time", t=5, message_count=10)
    run_server("signing", "time", t=3, message_count=50)

    # BBS+ Verification Time
    print("\n--- BBS+ Verification Time ---")
    client_data_10_msgs = run_client(10)
    run_server("verify", "time", client_data=client_data_10_msgs)
    client_data_50_msgs = run_client(50)
    run_server("verify", "time", client_data=client_data_50_msgs)
    client_data_100_msgs = run_client(100)
    run_server("verify", "time", client_data=client_data_100_msgs)

    # BBS+ Proof Gen & Verify Time
    print("\n--- BBS+ Proof Generation & Verification Time ---")
    client_data_50_rev_5 = run_client(50, 5)
    run_server("proof_gen", "time", client_data=client_data_50_rev_5)
    run_server("proof_verify", "time", client_data=client_data_50_rev_5)

    client_data_100_rev_10 = run_client(100, 10)
    run_server("proof_gen", "time", client_data=client_data_100_rev_10)
    run_server("proof_verify", "time", client_data=client_data_100_rev_10)

    print("\n" + "="*60)
    print("Running Cryptographic Protocol Benchmark Suite (Memory Measurement)")
    print("Each operation is run 10 times.")
    print("="*60)

    # Distributed Key Generation (DKG) Memory
    print("\n--- Distributed Key Generation (DKG) Memory ---")
    run_server("dkg", "memory", n=5, t=3)
    run_server("dkg", "memory", n=10, t=5)
    run_server("dkg", "memory", n=20, t=10)

    # Distributed Signing Memory
    print("\n--- Distributed Signing Memory ---")
    run_server("signing", "memory", t=3, message_count=10)
    run_server("signing", "memory", t=5, message_count=10)
    run_server("signing", "memory", t=3, message_count=50)

    # BBS+ Verification Memory
    print("\n--- BBS+ Verification Memory ---")
    client_data_10_msgs_mem = run_client(10)
    run_server("verify", "memory", client_data=client_data_10_msgs_mem)
    client_data_50_msgs_mem = run_client(50)
    run_server("verify", "memory", client_data=client_data_50_msgs_mem)
    client_data_100_msgs_mem = run_client(100)
    run_server("verify", "memory", client_data=client_data_100_msgs_mem)

    # BBS+ Proof Gen & Verify Memory
    print("\n--- BBS+ Proof Generation & Verification Memory ---")
    client_data_50_rev_5_mem = run_client(50, 5)
    run_server("proof_gen", "memory", client_data=client_data_50_rev_5_mem)
    run_server("proof_verify", "memory", client_data=client_data_50_rev_5_mem)

    client_data_100_rev_10_mem = run_client(100, 10)
    run_server("proof_gen", "memory", client_data=client_data_100_rev_10_mem)
    run_server("proof_verify", "memory", client_data=client_data_100_rev_10_mem)
    
    print("\n" + "="*60)
    print("Running Cryptographic Protocol Security Tests")
    print("Each test runs once to check for correct behavior.")
    print("="*60)
    
    test_unforgeability()
    test_unlinkability()

    print("\n" + "="*60)
    print("Benchmark and security suite finished.")
    print("="*60)

if __name__ == "__main__":
    main()