import hashlib
import random


class BLSAggregate:
    """
    BLS-Like Aggregate Signature Implementation
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
        Fast modular exponentiation: (base^exp) % modulus
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
        Hash a message to an exponent using SHA256.
        """
        h = hashlib.sha256(message.encode('utf-8')).digest()
        return int.from_bytes(h, 'big') % self.r

    def compute_g1_element(self, exponent):
        """
        Compute element in G1 group: g1^exponent % P
        """
        return self.mod_exp(self.g1, exponent, self.P)

    def compute_g2_element(self, exponent):
        """
        Compute element in G2 group: g2^exponent % P
        """
        return self.mod_exp(self.g2, exponent, self.P)

    def pairing_function(self, exp_g1, exp_g2):
        """
        Simplified bilinear pairing: (exp_g1 * exp_g2) % r
        """
        return (exp_g1 * exp_g2) % self.r


class Signer:
    """
    Signer class for managing keys, messages, and signatures
    """

    def __init__(self, bls, name):
        """
        Initialize a signer with a unique name and keypair.
        """
        self.bls = bls
        self.name = name
        self.sk, self.pk_exp, self.pk_numeric = self.keygen()
        self.messages = []  # List to store signed messages
        self.signatures = []  # List to store generated signatures

    def keygen(self):
        """
        Generate a keypair for the signer.
        """
        sk = random.randrange(1, self.bls.r)
        pk_exp = sk
        pk_numeric = self.bls.compute_g2_element(pk_exp)
        return sk, pk_exp, pk_numeric

    def sign_message(self, message):
        """
        Sign a message using the secret key.
        """
        h_exp = self.bls.hash_to_exponent(message)
        sig_exp = (h_exp * self.sk) % self.bls.r
        sig_numeric = self.bls.compute_g1_element(sig_exp)
        self.messages.append(message)
        self.signatures.append((sig_exp, sig_numeric))
        return sig_exp, sig_numeric
