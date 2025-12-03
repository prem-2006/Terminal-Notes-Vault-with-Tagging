import unittest
import os
import json
from terminal_vault.core.vault import Vault

class TestVault(unittest.TestCase):
    def setUp(self):
        self.test_file = "test_vault.json"
        self.vault = Vault(self.test_file)

    def tearDown(self):
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def test_create_and_unlock(self):
        self.vault.create_new("masterpass")
        self.assertFalse(self.vault.is_locked)
        
        self.vault.lock()
        self.assertTrue(self.vault.is_locked)
        
        self.assertTrue(self.vault.unlock("masterpass"))
        self.assertFalse(self.vault.is_locked)
        
        self.assertFalse(self.vault.unlock("wrongpass"))

    def test_add_get_entry(self):
        self.vault.create_new("masterpass")
        self.vault.add_entry("Gmail", "secret123", ["email", "personal"])
        self.vault.save()
        
        # Reload
        new_vault = Vault(self.test_file)
        new_vault.unlock("masterpass")
        entries = new_vault.get_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['title'], "Gmail")
        self.assertEqual(entries[0]['secret'], "secret123")
        
        # Filter
        email_entries = new_vault.get_entries("email")
        self.assertEqual(len(email_entries), 1)
        
        work_entries = new_vault.get_entries("work")
        self.assertEqual(len(work_entries), 0)

if __name__ == '__main__':
    unittest.main()
