from common.elliptic_curve_config import FIELD_ORDER, G2_GENERATOR, G2_INFINITY
from py_ecc.optimized_bls12_381 import multiply, add

def modular_inverse(a: int, m: int) -> int:
    """
    Compute the multiplicative inverse of a modulo m.
    Use the built-in pow(a, -1, m) function in Python 3.8+, 
    which uses the Extended Euclidean Algorithm under the hood, 
    the most efficient and safest approach.
    For example: (a * modular_inverse(a, m)) % m == 1
    """
    if a == 0:
        raise ValueError("0 has no modular inverse")
    if m <= 1:
        raise ValueError("The modulus must be greater than 1")
    
    # Compute modular inverse
    return pow(a, -1, m)


def lagrange_basis(points_x: list[int], i: int, x: int, field_order: int) -> int:
    """
    Computes the Lagrange basis polynomial L_i(x).
    points_x: List of x-coordinates of the points involved in the interpolation [x_0, x_1, ..., x_k].
    i: The i-th basis polynomial L_i is being evaluated.
    x: The point to be evaluated.
    """
    
    xi = points_x[i]
    numerator = 1
    denominator = 1

    for j, xj in enumerate(points_x):
        if i == j:
            continue
        numerator = (numerator * (x - xj))
        denominator = (denominator * (xi - xj))

    final_denominator = denominator % field_order
    final_numerator = numerator % field_order
    
    inv_denominator = modular_inverse(final_denominator, field_order)
    
    return (final_numerator * inv_denominator) % field_order


def interpolate_polynomial(points: list[tuple[int, int]], x: int, field_order: int) -> int:
    """
    Computes the polynomial at a given set of points using Lagrange interpolation.
    points: A list of tuples containing (x, y) coordinate pairs.
    Example: [(1, p(1)), (2, p(2)), (3, p(3))]
    x: The point to evaluate, e.g. 0 (for recovering the secret p(0)).
    """
    if not points:
        raise ValueError("Point set cannot be empty")

    points_x = [p[0] for p in points]
    points_y = [p[1] for p in points]
    
    result = 0
    for i in range(len(points)):
        y_i = points_y[i]
        basis_val = lagrange_basis(points_x, i, x, field_order)
        term = (y_i * basis_val) % field_order
        result = (result + term) % field_order
        
    return result

def interpolate_g2_points(points: dict, x_new: int) -> tuple:
    """
    Computes the value of a polynomial at x_new given a set of G2 points using Lagrange interpolation.
    This is an extension of `math_utils.interpolate_polynomial` for elliptic curve points.

    Args:
        points (dict): A dictionary of points of the form {x_coord: G2_Point}.
        x_new (int): The new x-coordinate at which the value is to be evaluated.

    Returns:
        tuple: A point representing the interpolated result on the G2 curve.
    """
    points_x = list(points.keys())
    points_y = list(points.values())

    result_point = G2_INFINITY

    for i in range(len(points_x)):
        y_i_point = points_y[i]
        basis_val = lagrange_basis(points_x, i, x_new, FIELD_ORDER)
        term = multiply(y_i_point, basis_val)
        result_point = add(result_point, term)
        
    return result_point

def interpolate_scalars(points: dict, x_new: int) -> int:
    """
    Computes the polynomial at x_new given a set of scalar points using Lagrange interpolation.
    This is the key function needed to recover the master private key x = p(0).

    Args:
        points (dict): A dictionary of points of the form {x_coord: scalar_value}.
        x_new (int): The new x-coordinate for which the value is to be evaluated (e.g., 0).

    Returns:
        int: The interpolation result (a scalar).
    """
    points_x = list(points.keys())
    points_y = list(points.values())

    result_scalar = 0
    for i in range(len(points_x)):
        y_i = points_y[i]
        basis_val = lagrange_basis(points_x, i, x_new, FIELD_ORDER)
        term = (y_i * basis_val) % FIELD_ORDER
        result_scalar = (result_scalar + term) % FIELD_ORDER
        
    return result_scalar