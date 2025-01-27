import hashlib
import random


class BLS:
    """
    BLS-Like Signature Scheme for Demonstration.
    """

    def __init__(self, prime_bits=127):
        """
        Initialize global constants for the BLS scheme.
        """
        self.P = 2 ** prime_bits - 1  # A large prime modulus
        self.r = self.P - 1  # Simplified group order
        self.g1 = 5  # Simplified generator for G1
        self.g2 = 7  # Simplified generator for G2
        self.g_t = 11  # Simplified generator for GT

    def mod_exp(self, base, exp, modulus):
        """
        Fast exponentiation: (base^exp) mod modulus.
        """
        result = 1
        cur = base % modulus
        e = exp
        while e > 0:
            if (e & 1) == 1:
                result = (result * cur) % modulus
            cur = (cur * cur) % modulus
            e >>= 1
        return result

    def hash_to_exponent(self, message):
        """
        Hash the message (SHA256) and convert to an integer mod r.
        """
        h = hashlib.sha256(message.encode('utf-8')).digest()
        num = int.from_bytes(h, 'big')
        return num % self.r

    def compute_g1_element(self, exponent):
        """
        Compute numeric representation of a G1 point: g1^exponent mod P.
        """
        return self.mod_exp(self.g1, exponent, self.P)

    def compute_g2_element(self, exponent):
        """
        Compute numeric representation of a G2 point: g2^exponent mod P.
        """
        return self.mod_exp(self.g2, exponent, self.P)

    def pairing_function(self, exp_g1, exp_g2):
        """
        Bilinear pairing demonstration: e: G1 x G2 -> GT in exponent form.
        Computes (exp_g1 * exp_g2) mod r as the pairing exponent.
        """
        return (exp_g1 * exp_g2) % self.r

    def keygen(self):
        """
        Generate a key pair.
        - Secret key: sk in [1, r-1]
        - Public key: pk_exp = sk as exponent, pk_numeric = g2^sk mod P
        """
        sk = random.randrange(1, self.r)
        pk_exp = sk
        pk_numeric = self.compute_g2_element(pk_exp)
        return sk, pk_exp, pk_numeric

    def sign_message(self, sk, message):
        """
        Sign a message using the secret key.
        - Signature (exponent form): sig_exp = (hashExp(m) * sk) mod r
        - Numeric form: g1^sig_exp mod P
        """
        h_exp = self.hash_to_exponent(message)
        sig_exp = (h_exp * sk) % self.r
        sig_numeric = self.compute_g1_element(sig_exp)
        return sig_exp, sig_numeric

    def verify_signature(self, pk_exp, message, sig_exp):
        """
        Verify a signature.
        - Check if e(sig, g2) == e(H(m), pk).
        - Demonstration: left_side = sig_exp, right_side = h_exp * pk_exp mod r
        """
        h_exp = self.hash_to_exponent(message)
        left_side = self.pairing_function(sig_exp, 1)
        right_side = self.pairing_function(h_exp, pk_exp)
        return h_exp, left_side, right_side, (left_side == right_side)