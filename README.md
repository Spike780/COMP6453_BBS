# Distributed BBS+ Signature in Python

This project aims to implement a threshold-based distributed BBS+ signature protocol in Python. This implementation covers the entire process from Distributed Key Generation (DKG) to signature generation, reconstruction, and verification.

## Project Introduction

The project simulates a network of `n` servers, where any `t` servers can cooperate to generate a valid BBS+ signature without ever reconstructing the master private key. This enhances the security of the private key and prevents a single point of failure.

The main process includes:
1.  **Distributed Key Generation (DKG)**: `n` servers jointly generate a master public key and their respective private key shares.
2.  **Distributed Signing**: `t` servers cooperate to generate signature shares (fragments) for a given message.
3.  **Reconstruction & Verification**: A client (or coordinator) collects `t` signature shares, aggregates them into a complete BBS+ signature, and verifies it using the master public key.

## Core Features

* **Distributed Key Generation**: Implements the DKG protocol (`π_DLKeyGen`) based on Shamir's Secret Sharing and Pedersen commitments, including consistency checks.
* **Core BBS+ Signature/Verification**: Implements the standard (centralized) BBS+ signing and verification logic, which can be used for final validation.
* **BBS+ Zero-Knowledge Proofs**: Implements the generation and verification of zero-knowledge proofs for BBS+ signatures, allowing for selective disclosure of messages.
* **Signature Share Reconstruction**: Implements the logic to aggregate signature shares (`SignatureShare`) from multiple servers into a final signature.
* **End-to-End Simulation**: `multi_party_simulation.py` provides a complete, end-to-end simulation flow, demonstrating the entire process from key generation to signature verification.

## Project Structure

```
.
├── benchmarking/
│   └── bankmark.py               # Performance benchmark script
├── common/
│   ├── bbsp.py                   # Core logic for BBS+ signing, verification, and proofs
│   ├── test_bbsp.py              # Tests for BBS+
│   ├── elliptic_curve_config.py  # Elliptic curve parameter configuration (e.g., BLS12-381)
│   └── math_utils.py             # Math utilities (modular inverse, Lagrange interpolation, etc.)
├── distributed_keygen/
│   ├── keygen_protocol.py        # Distributed Key Generation protocol implementation
│   ├── test_keygen_protocol.py   # Tests for the Distributed Key Generation protocol
│   └── shamir.py                 # Shamir's Secret Sharing algorithm
├── distributed_signing/
│   ├── test_distributed_signing_protocol.py. # Tests for the overall distributed signing protocol
│   └── signing_protocol.py       # Distributed signing protocol implementation
├── signature_reconstruction/
│   ├── test_reconstructor.py     # Tests for signature share reconstruction
│   └── reconstructor.py          # Signature share reconstruction logic
├── simulation/
│   └── multi_party_simulation.py # Multi-party end-to-end simulation flow
├── README.md                     # Project README file
└── requirements.txt              # Project dependencies
```

## Environment Requirements
* **Python 3.8+**

## How to Run

This project depends on the `py_ecc` library.

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run Simulation**:
    Execute the simulation file. It will run the complete DKG and distributed signing process, demonstrating the completion of DKG, the servers participating in the signing, the generation of signature shares, the reconstruction of the final signature, and the verification result.
    ```bash
    python -m distributed_signing.test_distributed_signing_protocol
    ```

3.  **Run Performance Benchmarks**:
    Execute the performance benchmark file. It will output the average time and memory consumption for operations such as DKG, signing, verification, and proof generation.
    ```bash
    python -m benchmarking.bankmark
    ```

4.  **Run Unit Tests**:
    The project includes a rich set of unit tests to ensure the correctness of each module.
    ```bash
    python -m distributed_keygen.test_keygen_protocol
    python -m common.test_bbsp
    python -m signature_reconstruction.test_reconstructor
    ```   
## Known Issues

* The `verify_proof` function is currently experimental and may not pass all proof verification cases (e.g., certain commitments may cause mismatches between T and T').