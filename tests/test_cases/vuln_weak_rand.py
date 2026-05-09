import random

# VULNERABILITY: weak PRNG
N = 3488
K = 2720
T = 64


def generate_secret():
    """Genere un secret avec un PRNG non cryptographique."""
    byte_value = random.randint(0, 255)
    bit_value = random.getrandbits(128)
    return byte_value, bit_value
