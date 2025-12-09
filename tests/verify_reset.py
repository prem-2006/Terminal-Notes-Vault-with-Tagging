
import unittest
from unittest.mock import patch
import os
import shutil
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from terminal_vault.cli.main import main
from terminal_vault.core.vault import Vault

class TestResetCredentials(unittest.TestCase):
    def setUp(self):
        self.test_vault = 'test_vault.json'
        self.test_csv = 'test_vault.csv'
        self.test_dat = 'test_vault.dat'
        
        # Clean up
        for f in [self.test_vault, self.test_csv, self.test_dat]:
            if os.path.exists(f):
                os.remove(f)

        # Create initial vault with data
        self.vault = Vault(self.test_vault)
        self.vault.create_new('old_user', 'old_pass')
        self.vault.add_entry('Secret Plan', 'World Domination', ['top-secret'])
        self.vault.save()
        
        # Verify CSV exists
        self.assertTrue(os.path.exists(self.test_csv))
        
        # Mock Config to use test_vault
        self.config_patcher = patch('terminal_vault.cli.main.Config')
        self.mock_config_cls = self.config_patcher.start()
        self.mock_config = self.mock_config_cls.return_value
        self.mock_config.get.return_value = self.test_vault

    def tearDown(self):
        self.config_patcher.stop()
        for f in [self.test_vault, self.test_csv, self.test_dat]:
            if os.path.exists(f):
                os.remove(f)

    @patch('terminal_vault.cli.main.getpass.getpass')
    @patch('builtins.input')
    def test_reset_credentials(self, mock_input, mock_getpass):
        # Setup inputs for reset flow:
        # confirmed (yes) -> new_user -> new_pass -> confirm_pass
        
        # Note: input() is called for:
        # 1. confirm_reset "yes"
        # 2. new_username "new_admin"
        
        # getpass() is called for:
        # 1. new_password "new_secret"
        # 2. confirm_password "new_secret"
        
        mock_input.side_effect = ['yes', 'new_admin']
        mock_getpass.side_effect = ['new_secret', 'new_secret']
        
        # Emulate command line args
        with patch.object(sys, 'argv', ['vault', 'reset-credentials']):
            main()
            
        # Verify result
        # 1. New vault should be unlockable with new credentials
        new_vault = Vault(self.test_vault)
        success = new_vault.unlock('new_admin', 'new_secret')
        self.assertTrue(success, "Failed to unlock vault with new credentials")
        
        # 2. Data should be present
        entries = new_vault.get_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['title'], 'Secret Plan')
        self.assertEqual(entries[0]['username'], 'new_admin')

if __name__ == '__main__':
    unittest.main()
