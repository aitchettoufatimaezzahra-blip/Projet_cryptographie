import hmac
import secrets

N = 3488
K = 2720
T = 64


def generate_keypair():
    """Genere une paire de cles factice avec un alea cryptographique."""
    private_key = secrets.token_bytes(64)
    public_key = secrets.token_bytes(64)
    return public_key, private_key


def verify_key(expected_key, candidate_key):
    """Compare deux cles avec une fonction constant-time."""
    return hmac.compare_digest(expected_key, candidate_key)


def encapsulate():
    """Simule une encapsulation propre puis efface la cle privee."""
    public_key, private_key = generate_keypair()
    shared_secret = secrets.token_bytes(32)
    verify_key(public_key, public_key)
    del private_key
    return shared_secret
