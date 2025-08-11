from distributed_keygen.shamir import create_random_polynomial, evaluate_polynomial
from common.math_utils import lagrange_basis, interpolate_g2_points
from common.elliptic_curve_config import FIELD_ORDER, G2_GENERATOR, G2_INFINITY
from py_ecc.optimized_bls12_381  import multiply, add
from py_ecc.optimized_bls12_381.optimized_curve import normalize

class DistributedKeyGenerator:
    """
    Classes for simulating and executing distributed key generation protocols.
    """
    def __init__(self, n: int, t: int, field_order: int, curve_generator):
        if t > n:
            raise ValueError("The threshold value cannot be greater than the total number of servers")
        self.n = n
        self.t = t
        self.field_order = FIELD_ORDER
        self.G = G2_GENERATOR

    def run_protocol(self) -> tuple[dict, object]:
        """
        Runs the full key derivation protocol.

        Returns:
            - A dictionary {server_id:share} containing each server's private key share
            - The global public key X
        """
        # Each server calculates its final private key share and public key share
        server_polynomials = {
            i: create_random_polynomial(self.t - 1, self.field_order)
            for i in range(1, self.n + 1)
        }

        # Exchange points on polynomials between servers
        points_received_by_server = {j: [] for j in range(1, self.n + 1)}
        for i in range(1, self.n + 1):
            poly_coeffs = server_polynomials[i]
            for j in range(1, self.n + 1):
                point_for_j = evaluate_polynomial(poly_coeffs, j, self.field_order)
                points_received_by_server[j].append(point_for_j)

        # Each server calculates its final private key share and public key share
        # private key share p*(i) = Σ p_j(i)
        # public key share P(i) = p*(i) * G
        private_shares = {}
        public_shares = {}
        for i in range(1, self.n + 1):
            private_share_i = sum(points_received_by_server[i]) % self.field_order
            private_shares[i] = private_share_i
            public_shares[i] = multiply(self.G, private_share_i)

        # Perform consistency check
        self._perform_consistency_check(public_shares)

        # Calculate the global master public key
        # master_public_key X = P(0)
        master_public_key = self._calculate_master_public_key(public_shares)

        return private_shares, master_public_key

    def _perform_consistency_check(self, public_shares: dict) -> bool:
        """
        Verify that all public key shares lie on the same t-1 order polynomial.
        """
        if self.n < self.t:
            return

        # Select the first t public key shares to define the polynomial
        sample_points = {i: public_shares[i] for i in range(1, self.t + 1)}
        
        # Check whether the remaining n-t points conform to the polynomial
        for i in range(self.t + 1, self.n + 1):
            point_to_check = normalize(public_shares[i])
            # Calculate the expected value of P(i) by interpolating the first t points
            interpolated_point = normalize(interpolate_g2_points(sample_points, i))
            
            # print(f"Server {i} share: {point_to_check}")
            # print(f"Expected: {interpolated_point}")
            # print(f"Equal? {point_to_check == interpolated_point}")
            
            if interpolated_point != point_to_check:
                raise ValueError(f"Key generation failed: Public key share inconsistency! Server {i}'s share failed verification.")
        print("All public key shares passed the consistency check.")

    def _calculate_master_public_key(self, public_shares: dict) -> object:
        """
        Calculate the final global public key X = P(0) from t public key shares.
        """
        sample_points = {i: public_shares[i] for i in range(1, self.t + 1)}
        
        # Compute the value at x=0 using Lagrange interpolation
        master_public_key = interpolate_g2_points(sample_points, 0)
        return master_public_key
    