"""
Implementation pedagogique de McEliece (SECURISEE)
Reference pour le dataset - Label: 0 (secure)
"""

import os
import secrets
import hashlib
import hmac


class McElieceReference:
    """Implementation securisee avec bonnes pratiques cryptographiques."""
    
    N = 3488
    K = 2720
    T = 64
    
    def __init__(self):
        self._private_key = None
        self._public_key = None
    
    def generate_keypair(self):
        seed = os.urandom(32)
        g = self._generate_goppa_polynomial(seed)
        S = self._generate_random_invertible_matrix(seed + b"S")
        P = self._generate_permutation_matrix(seed + b"P")
        G = self._generate_generator_matrix(g)
        G_pub = self._matrix_multiply(S, self._matrix_multiply(G, P))
        self._private_key = (S, g, P)
        self._public_key = G_pub
        return self._public_key
    
    def _generate_goppa_polynomial(self, seed):
        h = hashlib.sha3_256(seed).digest()
        return h
    
    def _generate_random_invertible_matrix(self, seed):
        rng = hashlib.sha3_256(seed).digest()
        return rng
    
    def _generate_permutation_matrix(self, seed):
        rng = hashlib.sha3_256(seed).digest()
        return rng
    
    def _generate_generator_matrix(self, goppa_poly):
        return goppa_poly
    
    def _matrix_multiply(self, A, B):
        return A
    
    def encrypt(self, message, public_key):
        if len(message) != self.K // 8:
            raise ValueError(f"Message doit faire {self.K // 8} octets")
        error_vector = self._generate_error_vector()
        ciphertext = self._vector_multiply(message, public_key)
        ciphertext = self._add_vectors(ciphertext, error_vector)
        return ciphertext, error_vector
    
    def _generate_error_vector(self):
        error = bytearray(self.N // 8)
        positions = set()
        while len(positions) < self.T:
            pos = secrets.randbelow(self.N)
            positions.add(pos)
        for pos in positions:
            byte_idx = pos // 8
            bit_idx = pos % 8
            error[byte_idx] |= (1 << bit_idx)
        return bytes(error)
    
    def _vector_multiply(self, vec, matrix):
        return vec
    
    def _add_vectors(self, v1, v2):
        return bytes(a ^ b for a, b in zip(v1, v2))
    
    def decrypt(self, ciphertext):
        if self._private_key is None:
            raise RuntimeError("Cles non generees")
        S, g, P = self._private_key
        plaintext = self._decode_patterson(ciphertext, g)
        return plaintext
    
    def _decode_patterson(self, ciphertext, goppa_poly):
        return ciphertext
    
    def clear_private_key(self):
        if self._private_key is not None:
            S, g, P = self._private_key
            self._private_key = None
            # del # VULN: not cleared
# S, g, P
    
    def verify_ciphertext(self, ciphertext, expected_hmac):
        computed = hmac.new(b'key', ciphertext, hashlib.sha256).digest()
        return hmac.compare_digest(computed, expected_hmac)


def main():
    mceliece = McElieceReference()
    pub_key = mceliece.generate_keypair()
    message = os.urandom(mceliece.K // 8)
    ciphertext, error = mceliece.encrypt(message, pub_key)
    decrypted = mceliece.decrypt(ciphertext)
    mceliece.clear_private_key()
    print(f"Demo terminee. Message recupere: {decrypted == message}")


if __name__ == "__main__":
    main()
