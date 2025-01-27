import unittest
from singleBls.singleBlsAlg import BLS


class TestBLSFunctions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Setup common constants for all tests."""
        cls.bls = BLS()
        cls.message = "Hello, BLS!"
        cls.alternative_message = "Different Message"
        cls.sk, cls.pk_exp, cls.pk_numeric = cls.bls.keygen()
        print(f"Generated Keys:\nSecret Key (sk): {cls.sk}\nPublic Key Exponent (pk_exp): {cls.pk_exp}\nPublic Key Numeric (pk_numeric): {cls.pk_numeric}\n")

    def test_key_generation(self):
        """Test that the key generation produces valid keys."""
        print("Running test_key_generation...")
        sk, pk_exp, pk_numeric = self.sk, self.pk_exp, self.pk_numeric
        self.assertGreater(sk, 0, "Secret key should be greater than 0.")
        self.assertGreater(pk_exp, 0, "Public key exponent should be greater than 0.")
        self.assertGreater(pk_numeric, 0, "Public key numeric should be greater than 0.")
        print("Key generation passed.\n")

    def test_hash_to_exponent(self):
        """Test that the hash function maps a message to a valid exponent."""
        print("Running test_hash_to_exponent...")
        h_exp = self.bls.hash_to_exponent(self.message)
        print(f"Message: {self.message}\nHash Exponent: {h_exp}")
        self.assertGreater(h_exp, 0, "Hashed exponent should be greater than 0.")
        print("Hash to exponent passed.\n")

    def test_sign_message(self):
        """Test signing a message."""
        print("Running test_sign_message...")
        sig_exp, sig_numeric = self.bls.sign_message(self.sk, self.message)
        print(f"Message: {self.message}\nSignature Exponent: {sig_exp}\nSignature Numeric: {sig_numeric}")
        self.assertGreater(sig_exp, 0, "Signature exponent should be greater than 0.")
        self.assertGreater(sig_numeric, 0, "Signature numeric should be greater than 0.")
        print("Sign message passed.\n")

    def test_verify_signature_valid(self):
        """Test verifying a valid signature."""
        print("Running test_verify_signature_valid...")
        sig_exp, _ = self.bls.sign_message(self.sk, self.message)
        h_exp, left_side, right_side, is_valid = self.bls.verify_signature(self.pk_exp, self.message, sig_exp)
        print(f"Verification Details:\nHash Exponent: {h_exp}\nLeft Side: {left_side}\nRight Side: {right_side}\nResult: {'Valid' if is_valid else 'Invalid'}")
        self.assertTrue(is_valid, "Signature should be valid for the correct message.")
        print("Verify valid signature passed.\n")

    def test_verify_signature_invalid(self):
        """Test verifying an invalid signature."""
        print("Running test_verify_signature_invalid...")
        sig_exp, _ = self.bls.sign_message(self.sk, self.message)
        h_exp, left_side, right_side, is_valid = self.bls.verify_signature(self.pk_exp, self.alternative_message, sig_exp)
        print(f"Verification Details (Invalid Message):\nHash Exponent: {h_exp}\nLeft Side: {left_side}\nRight Side: {right_side}\nResult: {'Valid' if is_valid else 'Invalid'}")
        self.assertFalse(is_valid, "Signature should be invalid for a different message.")
        print("Verify invalid signature passed.\n")

    def test_mod_exp(self):
        """Test modular exponentiation."""
        print("Running test_mod_exp...")
        base = 5
        exp = 3
        modulus = 17
        result = self.bls.mod_exp(base, exp, modulus)
        expected = (base ** exp) % modulus
        print(f"Base: {base}, Exponent: {exp}, Modulus: {modulus}\nResult: {result}, Expected: {expected}")
        self.assertEqual(result, expected, "Modular exponentiation should return the correct result.")
        print("Modular exponentiation passed.\n")

    def test_compute_g1_element(self):
        """Test computing G1 elements."""
        print("Running test_compute_g1_element...")
        exponent = 10
        g1_element = self.bls.compute_g1_element(exponent)
        expected = self.bls.mod_exp(self.bls.g1, exponent, self.bls.P)
        print(f"Exponent: {exponent}\nG1 Element: {g1_element}, Expected: {expected}")
        self.assertEqual(g1_element, expected, "G1 element computation should match expected result.")
        print("Compute G1 element passed.\n")

    def test_compute_g2_element(self):
        """Test computing G2 elements."""
        print("Running test_compute_g2_element...")
        exponent = 15
        g2_element = self.bls.compute_g2_element(exponent)
        expected = self.bls.mod_exp(self.bls.g2, exponent, self.bls.P)
        print(f"Exponent: {exponent}\nG2 Element: {g2_element}, Expected: {expected}")
        self.assertEqual(g2_element, expected, "G2 element computation should match expected result.")
        print("Compute G2 element passed.\n")

if __name__ == "__main__":
    unittest.main()
