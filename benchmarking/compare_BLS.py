import time
import statistics
import tracemalloc
import random
import hashlib
from py_ecc.optimized_bls12_381 import (
    multiply, G1, G2, add, pairing, final_exponentiate
)


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


# Simple BLS signature implementation for demonstration purposes
class BLS:
    @staticmethod
    def KeyGen():
        # Generates a BLS key pair
        FIELD_ORDER = 0x73eda753299d7d483339d80871ab000000000000000000000000000000000001
        sk = random.randint(1, FIELD_ORDER - 1)
        pk = multiply(G2, sk)
        return sk, pk

    @staticmethod
    def Sign(sk, message):
        # Sign single message
        FIELD_ORDER = 0x73eda753299d7d483339d80871ab000000000000000000000000000000000001
        # Hash message to a point on G1
        h = hashlib.sha256(str(message).encode()).digest()
        H_point = multiply(G1, int.from_bytes(h, 'big') % FIELD_ORDER)
        signature = multiply(H_point, sk)
        return signature

    @staticmethod
    def Verify(pk, message, signature):
        # Verfify message
        FIELD_ORDER = 0x73eda753299d7d483339d80871ab000000000000000000000000000000000001
        h = hashlib.sha256(str(message).encode()).digest()
        H_point = multiply(G1, int.from_bytes(h, 'big') % FIELD_ORDER)
        
        # Verify e(pk, H(m)) == e(G2, signature)
        # Correctly calling pairing(G2_point, G1_point)
        pairing1 = pairing(pk, H_point)
        pairing2 = pairing(G2, signature)
        
        return final_exponentiate(pairing1) == final_exponentiate(pairing2)
    
    @staticmethod
    def batch_verify(pk_list, message_list, signature_list):
        """Batch verifies multiple BLS signatures."""
        if len(pk_list) != len(message_list) or len(message_list) != len(signature_list):
            raise ValueError("All lists must have the same length.")

        # Aggregate the public keys and signatures for batch verification
        FIELD_ORDER = 0x73eda753299d7d483339d80871ab000000000000000000000000000000000001
        H_points = [multiply(G1, int.from_bytes(hashlib.sha256(str(msg).encode()).digest(), 'big') % FIELD_ORDER) for msg in message_list]
        
        # Aggregate G2 points
        pk_sum = pk_list[0]
        for i in range(1, len(pk_list)):
            pk_sum = add(pk_sum, pk_list[i])

        # Aggregate G1 points
        H_sum = H_points[0]
        for i in range(1, len(H_points)):
            H_sum = add(H_sum, H_points[i])
            
        sig_sum = signature_list[0]
        for i in range(1, len(signature_list)):
            sig_sum = add(sig_sum, signature_list[i])
            
        pairing1 = pairing(pk_sum, H_sum)
        pairing2 = pairing(G2, sig_sum)
        
        return final_exponentiate(pairing1) == final_exponentiate(pairing2)

def run_bls_benchmark(mode, measure_mode, message_count):
    # Benchmarks BLS signing and verification
    times = []
    memory_usages = []
    
    sk, pk = BLS.KeyGen()
    messages = [random.randint(1, 10000) for _ in range(message_count)]
    signatures = [BLS.Sign(sk, msg) for msg in messages]

    op_func = None
    op_name = ""
    if mode == "bls_sign":
        op_name = f"BLS Sign ({message_count} msgs)"
        op_func = lambda: [BLS.Sign(sk, msg) for msg in messages]
    elif mode == "bls_verify":
        op_name = f"BLS Verify ({message_count} msgs)"
        op_func = lambda: [BLS.Verify(pk, messages[i], signatures[i]) for i in range(message_count)]
    elif mode == "bls_batch_verify":
        op_name = f"BLS Batch Verify ({message_count} msgs)"
        op_func = lambda: BLS.batch_verify([pk] * message_count, messages, signatures)
    else:
        return

    for _ in range(BENCHMARK_ROUNDS):
        if measure_mode == "time":
            start = time.perf_counter()
            op_func()
            end = time.perf_counter()
            times.append(end - start)
        elif measure_mode == "memory":
            tracemalloc.start()
            op_func()
            _, peak_memory = tracemalloc.get_traced_memory()
            memory_usages.append(peak_memory)
            tracemalloc.stop()

    if measure_mode == "time":
        print_results_time(op_name, times)
    elif measure_mode == "memory":
        print_results_memory(op_name, memory_usages)

def main():
    print("="*60)
    print("Running BLS Signature Benchmark Suite (Time Measurement)")
    print("Each operation is run 10 times.")
    print("="*60)
    
    # BLS Signature Time
    print("\n--- BLS Signature Time (for Comparison) ---")
    run_bls_benchmark("bls_sign", "time", 10)
    run_bls_benchmark("bls_verify", "time", 10)
    run_bls_benchmark("bls_sign", "time", 50)
    run_bls_benchmark("bls_verify", "time", 50)
    run_bls_benchmark("bls_sign", "time", 100)
    run_bls_benchmark("bls_verify", "time", 100)
    
    # BLS Batch Verification Time
    print("\n--- BLS Batch Verification Time (for high-throughput scenarios) ---")
    run_bls_benchmark("bls_batch_verify", "time", 10)
    run_bls_benchmark("bls_batch_verify", "time", 50)
    run_bls_benchmark("bls_batch_verify", "time", 100)

    print("\n" + "="*60)
    print("Running BLS Signature Benchmark Suite (Memory Measurement)")
    print("Each operation is run 10 times.")
    print("="*60)

    # BLS Signature Memory
    print("\n--- BLS Signature Memory ---")
    run_bls_benchmark("bls_sign", "memory", 10)
    run_bls_benchmark("bls_verify", "memory", 10)
    run_bls_benchmark("bls_sign", "memory", 50)
    run_bls_benchmark("bls_verify", "memory", 50)
    run_bls_benchmark("bls_sign", "memory", 100)
    run_bls_benchmark("bls_verify", "memory", 100)

    # BLS Batch Verification Memory
    print("\n--- BLS Batch Verification Memory ---")
    run_bls_benchmark("bls_batch_verify", "memory", 10)
    run_bls_benchmark("bls_batch_verify", "memory", 50)
    run_bls_benchmark("bls_batch_verify", "memory", 100)

    print("\n" + "="*60)
    print("Benchmark suite finished.")
    print("="*60)

if __name__ == "__main__":
    main()
