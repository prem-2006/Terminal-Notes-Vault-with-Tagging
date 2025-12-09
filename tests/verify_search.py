
import unittest
from unittest.mock import patch, MagicMock
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from terminal_vault.cli.main import main

class TestSearch(unittest.TestCase):
    @patch('terminal_vault.cli.main.authenticate')
    @patch('terminal_vault.cli.main.Vault')
    @patch('terminal_vault.cli.main.Config')
    @patch('builtins.print')
    def test_search_content(self, mock_print, mock_config, mock_vault_cls, mock_auth):
        # Setup Mock Vault
        mock_vault = mock_vault_cls.return_value
        mock_vault.get_entries.return_value = [
            {'title': 'The Secret Garden', 'note': 'A book about a garden', 'tags': ['book'], 'id': '1', 'date': '2023'},
            {'title': 'My Diary', 'note': 'This is a top Secret diary', 'tags': ['personal'], 'id': '2', 'date': '2023'},
            {'title': 'Shopping List', 'note': 'Milk, Bread, Eggs', 'tags': ['chore'], 'id': '3', 'date': '2023'}
        ]
        
        # Setup Mock Config
        mock_config.return_value.get.return_value = 'dummy.json'

        # Run command: vault get --search "Secret"
        with patch.object(sys, 'argv', ['vault', 'get', '--search', 'Secret']):
            main()
            
        # Verify output
        # Capture all print calls
        printed_lines = [str(call.args[0]) for call in mock_print.call_args_list if call.args]
        full_output = "\n".join(printed_lines)
        
        # We expect "Found 2 entries" or similar logic if implemented
        # And we expect the titles/notes to be printed
        
        self.assertIn("The Secret Garden", full_output)
        self.assertIn("My Diary", full_output)
        self.assertNotIn("Shopping List", full_output)

if __name__ == '__main__':
    unittest.main()
