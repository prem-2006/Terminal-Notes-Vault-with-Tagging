import unittest
import os
import shutil
import tempfile
from pathlib import Path
from src.crypto_utils import derive_key, encrypt_data, decrypt_data, calculate_entropy, estimate_strength
from src.vault import Vault
from src.security import LoginThrottler

class TestCryptoUtils(unittest.TestCase):
    def test_derive_key_deterministic(self):
        key1, salt1 = derive_key("password")
        key2, salt2 = derive_key("password", salt1)
        self.assertEqual(key1, key2)
        self.assertEqual(salt1, salt2)

    def test_derive_key_random(self):
        key1, salt1 = derive_key("password")
        key2, salt2 = derive_key("password")
        self.assertNotEqual(salt1, salt2)
        self.assertNotEqual(key1, key2)

    def test_encryption_decryption(self):
        key, _ = derive_key("password")
        data = "Secret Message"
        encrypted = encrypt_data(data, key)
        decrypted = decrypt_data(encrypted, key)
        self.assertEqual(data, decrypted)

    def test_entropy(self):
        self.assertEqual(calculate_entropy("aaaa"), 0.0) # Zero entropy
        self.assertGreater(calculate_entropy("abcd"), 0.0)

    def test_strength(self):
        self.assertEqual(estimate_strength("123"), "Weak")
        self.assertEqual(estimate_strength("Password123!"), "Strong")

class TestVault(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.vault_path = os.path.join(self.test_dir, "test_vault.dat")
        self.vault = Vault(self.vault_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_create_vault(self):
        self.vault.create_vault("password")
        self.assertTrue(os.path.exists(self.vault_path))
        self.assertTrue(self.vault.is_unlocked)

    def test_add_and_get_entry(self):
        self.vault.create_vault("password")
        self.vault.add_entry("Gmail", "my_password", ["email", "personal"])
        
        entries = self.vault.get_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["title"], "Gmail")
        self.assertEqual(entries[0]["secret"], "my_password")

    def test_search(self):
        self.vault.create_vault("password")
        self.vault.add_entry("Gmail", "pass1", ["email"])
        self.vault.add_entry("Bank", "pass2", ["finance"])
        
        results = self.vault.search_entries("email")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["title"], "Gmail")

    def test_reopen_vault(self):
        self.vault.create_vault("password")
        self.vault.add_entry("Gmail", "pass1")
        
        # Create new instance
        new_vault = Vault(self.vault_path)
        new_vault.unlock("password")
        entries = new_vault.get_entries()
        self.assertEqual(len(entries), 1)

    def test_wrong_password(self):
        self.vault.create_vault("password")
        new_vault = Vault(self.vault_path)
        with self.assertRaises(ValueError):
            new_vault.unlock("wrong_password")

class TestThrottler(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.lock_file = os.path.join(self.test_dir, ".lock")
        self.throttler = LoginThrottler(self.lock_file)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_lockout(self):
        self.throttler.record_failure()
        self.throttler.record_failure()
        self.throttler.record_failure() # 3rd failure
        
        self.assertGreater(self.throttler.check_lockout(), 0)

if __name__ == '__main__':
    unittest.main()
