import unittest
from terminal_vault.core.security import calculate_entropy, derive_key, xor_bytes

class TestSecurity(unittest.TestCase):
    def test_entropy(self):
        self.assertEqual(calculate_entropy(""), 0.0)
        self.assertGreater(calculate_entropy("password"), 0)
        self.assertGreater(calculate_entropy("P@ssw0rd123!"), calculate_entropy("password"))

    def test_derive_key(self):
        salt = b'salt'
        key1 = derive_key("password", salt)
        key2 = derive_key("password", salt)
        self.assertEqual(key1, key2)
        
        key3 = derive_key("wrong", salt)
        self.assertNotEqual(key1, key3)

    def test_xor_bytes(self):
        data = b"hello"
        key = b"key"
        encrypted = xor_bytes(data, key)
        decrypted = xor_bytes(encrypted, key)
        self.assertEqual(data, decrypted)

if __name__ == '__main__':
    unittest.main()
