import secrets

def create_random_polynomial(degree: int, field_order: int) -> list[int]:
    """
    Creates a random polynomial of degree t-1.
    Returns the list of coefficients of the polynomial [c0, c1, ..., c_{degree}], where c0 is a secret.
    The coefficients should be random integers from 0 to field_order-1.
    """
    if degree < 0:
        return []
    return [secrets.randbelow(field_order) for _ in range(degree + 1)]


def evaluate_polynomial(coeffs: list[int], x: int, field_order: int) -> int:
    """
    Evaluate the polynomial at the point x (using Horner's rule for greater efficiency).
    """
    if not coeffs:
        return 0
    
    result = 0
    for coeff in reversed(coeffs):
        result = (result * x + coeff) % field_order
    return result

