# VULNERABILITY: timing leak
N = 3488
K = 2720
T = 64


def verify_key(expected_key, candidate_key):
    """Compare deux cles avec un operateur non constant-time."""
    return expected_key == candidate_key
