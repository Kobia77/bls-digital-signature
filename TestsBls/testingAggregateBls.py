import unittest
from aggregateBls.aggregateBlsAlg import BLSAggregate, Signer


class TestBLSAggregateFunctions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Setup common constants and instances for all tests."""
        cls.bls = BLSAggregate()
        cls.signer1 = Signer(cls.bls, "Alice")
        cls.signer2 = Signer(cls.bls, "Bob")
        cls.message = "Hello, Aggregate BLS!"
        cls.alternative_message = "Another Message"

    def test_key_generation(self):
        """Test that key generation produces valid keys for signers."""
        print("Running test_key_generation...")
        for signer in [self.signer1, self.signer2]:
            self.assertGreater(signer.sk, 0, f"{signer.name}'s secret key should be greater than 0.")
            self.assertGreater(signer.pk_exp, 0, f"{signer.name}'s public key exponent should be greater than 0.")
            self.assertGreater(signer.pk_numeric, 0, f"{signer.name}'s public key numeric should be greater than 0.")
        print("Key generation passed.\n")

    def test_hash_to_exponent(self):
        """Test that messages are hashed to valid exponents."""
        print("Running test_hash_to_exponent...")
        h_exp = self.bls.hash_to_exponent(self.message)
        print(f"Message: {self.message}\nHash Exponent: {h_exp}")
        self.assertGreater(h_exp, 0, "Hash exponent should be greater than 0.")
        print("Hash to exponent passed.\n")

    def test_sign_message(self):
        """Test that messages can be signed by a signer."""
        print("Running test_sign_message...")
        sig_exp, sig_numeric = self.signer1.sign_message(self.message)
        print(f"Message: {self.message}\nSignature Exponent: {sig_exp}\nSignature Numeric: {sig_numeric}")
        self.assertGreater(sig_exp, 0, "Signature exponent should be greater than 0.")
        self.assertGreater(sig_numeric, 0, "Signature numeric should be greater than 0.")
        print("Sign message passed.\n")

    def test_verify_signature_valid(self):
        """Test that valid signatures are correctly verified."""
        print("Running test_verify_signature_valid...")
        sig_exp, _ = self.signer1.sign_message(self.message)
        h_exp = self.bls.hash_to_exponent(self.message)
        left_side = self.bls.pairing_function(sig_exp, 1)
        right_side = self.bls.pairing_function(h_exp, self.signer1.pk_exp)
        print(f"Verification Details:\nHash Exponent: {h_exp}\nLeft Side: {left_side}\nRight Side: {right_side}\n")
        self.assertEqual(left_side, right_side, "Signature should be valid.")
        print("Verify valid signature passed.\n")

    def test_verify_signature_invalid(self):
        """Test that invalid signatures are rejected."""
        print("Running test_verify_signature_invalid...")
        sig_exp, _ = self.signer1.sign_message(self.message)
        h_exp = self.bls.hash_to_exponent(self.alternative_message)
        left_side = self.bls.pairing_function(sig_exp, 1)
        right_side = self.bls.pairing_function(h_exp, self.signer1.pk_exp)
        print(f"Verification Details (Invalid Message):\nHash Exponent: {h_exp}\nLeft Side: {left_side}\nRight Side: {right_side}\n")
        self.assertNotEqual(left_side, right_side, "Signature should be invalid for a different message.")
        print("Verify invalid signature passed.\n")

    def test_signer_message_tracking(self):
        """Test that signers track signed messages and signatures."""
        print("Running test_signer_message_tracking...")
        sig_exp, sig_numeric = self.signer2.sign_message(self.message)
        self.assertIn(self.message, self.signer2.messages, "Message should be tracked by the signer.")
        self.assertIn((sig_exp, sig_numeric), self.signer2.signatures, "Signature should be tracked by the signer.")
        print("Signer message tracking passed.\n")

if __name__ == "__main__":
    unittest.main()
