import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock
from io import StringIO

# Add src to path
sys.path.append(os.path.join(os.getcwd(), 'src'))

from terminal_vault.cli.main import main
from terminal_vault.core.vault import Vault

class TestVaultHiding(unittest.TestCase):
    def setUp(self):
        self.test_vault = 'test_vault.json'
        self.test_plain = 'test_vault_plain.json'
        
        # Create a dummy vault file
        with open(self.test_vault, 'w') as f:
            f.write('{}') # Invalid JSON but enough to exist, or mock it better
            
        # Mock Config to return test vault
        self.config_patcher = patch('terminal_vault.cli.main.Config')
        self.mock_config = self.config_patcher.start()
        self.mock_config.return_value.get.side_effect = lambda section, key: self.test_vault if key == 'vault_file' else 'test.log'

    def tearDown(self):
        self.config_patcher.stop()
        if os.path.exists(self.test_vault):
            os.remove(self.test_vault)
        if os.path.exists(self.test_plain):
            os.remove(self.test_plain)

    @patch('terminal_vault.cli.main.Vault')
    @patch('terminal_vault.cli.main.LockoutManager')
    def test_plain_file_deleted_on_startup(self, mock_lockout, mock_vault):
        # Create plain file
        with open(self.test_plain, 'w') as f:
            f.write('secret')
            
        # Run main with just help to trigger startup cleanup
        with patch('sys.argv', ['vault', '--help']):
            try:
                main()
            except SystemExit:
                pass
                
        # Check if file is gone
        self.assertFalse(os.path.exists(self.test_plain), "Plain file should be deleted on startup")

    @patch('sys.stdout', new_callable=StringIO)
    @patch('terminal_vault.cli.main.Vault')
    @patch('terminal_vault.cli.main.LockoutManager')
    @patch('terminal_vault.cli.main.authenticate')
    def test_show_plain_command(self, mock_auth, mock_lockout, mock_vault, mock_stdout):
        # Setup mock vault
        mock_vault_instance = mock_vault.return_value
        mock_vault_instance.get_entries.return_value = [{'title': 'Test', 'note': 'Secret'}]
        
        # Run show-plain command
        with patch('sys.argv', ['vault', 'show-plain']):
            main()
            
        # Check if file is created
        self.assertTrue(os.path.exists(self.test_plain), "Plain file should be created by show-plain")
        
        # Verify content
        with open(self.test_plain, 'r') as f:
            content = json.load(f)
            self.assertEqual(content[0]['title'], 'Test')

if __name__ == '__main__':
    unittest.main()
