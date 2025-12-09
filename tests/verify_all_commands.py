
import unittest
from unittest.mock import patch, MagicMock
import os
import sys
import shutil
import csv

# Ensure we import from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from terminal_vault.cli.main import main
from terminal_vault.core.vault import Vault

class TestAllCommands(unittest.TestCase):
    def setUp(self):
        self.test_prefix = 'test_full_suite'
        self.vault_file = f'{self.test_prefix}.json'
        self.csv_file = f'{self.test_prefix}.csv'
        self.dat_file = f'{self.test_prefix}.dat'
        self.plain_file = f'{self.test_prefix}_plain.json'
        
        # Cleanup
        self.cleanup()
        
        # Mock Config to use test vault
        self.config_patcher = patch('terminal_vault.cli.main.Config')
        self.mock_config_cls = self.config_patcher.start()
        self.mock_config = self.mock_config_cls.return_value
        self.mock_config.get.return_value = self.vault_file

    def tearDown(self):
        self.config_patcher.stop()
        self.cleanup()

    def cleanup(self):
        for f in [self.vault_file, self.csv_file, self.dat_file, self.plain_file]:
            if os.path.exists(f):
                try: os.remove(f)
                except: pass

    @patch('builtins.print')
    @patch('builtins.input')
    @patch('terminal_vault.cli.main.get_masked_input')
    @patch('sys.exit')
    def test_full_flow(self, mock_exit, mock_getpass, mock_input, mock_print):
        mock_exit.side_effect = Exception("SYS_EXIT_CALLED")
        
        try:
            # 1. INIT
            print("\n--- Testing INIT ---")
            mock_input.side_effect = ['admin'] # Username
            mock_getpass.side_effect = ['password123', 'password123'] # Password, Confirm
            
            with patch.object(sys, 'argv', ['vault', 'init']):
                main()
                
            self.assertTrue(os.path.exists(self.vault_file), "Vault file not created after INIT")
            
            # 2. ADD
            print("\n--- Testing ADD ---")
            # Auth (User, Pass) -> Note Content
            # Note: ADD command asks for NOTE via input()
            # authenticate asks for Username via input(), Password via getpass()
            # Sequence: Username (auth), Note (add)
            mock_input.side_effect = ['admin', 'This is a test note'] 
            mock_getpass.side_effect = ['password123']
            
            with patch.object(sys, 'argv', ['vault', 'add', '--title', 'Test Note 1', '--tags', 'work,test']):
                main()
                
            # Verify content logic via generic Vault read
            v = Vault(self.vault_file)
            v.unlock('admin', 'password123')
            self.assertEqual(len(v.entries), 1, "Entry not added")
            self.assertEqual(v.entries[0]['title'], 'Test Note 1')

            # 3. GET (Search)
            print("\n--- Testing GET ---")
            mock_input.side_effect = ['admin']
            mock_getpass.side_effect = ['password123']
            
            with patch.object(sys, 'argv', ['vault', 'get', '--search', 'Test']):
                main()


            # 4. REPORT
            print("\n--- Testing REPORT ---")
            mock_input.side_effect = ['admin']
            mock_getpass.side_effect = ['password123']
            
            with patch.object(sys, 'argv', ['vault', 'report']):
                main()

            # 5. USER (Change Credentials)
            print("\n--- Testing USER ---")
            # Auth (User, Pass) -> New User -> New Pass -> Confirm
            mock_input.side_effect = ['admin', 'new_admin']
            mock_getpass.side_effect = ['password123', 'newpassword456', 'newpassword456']
            
            with patch.object(sys, 'argv', ['vault', 'user']):
                main()
            
            # Verify new credentials work
            v = Vault(self.vault_file)
            self.assertTrue(v.unlock('new_admin', 'newpassword456'), "New credentials failed")

            # 6. RESET PASSWORD
            print("\n--- Testing RESET-PASSWORD ---")
            # Auth (New User, New Pass) -> New Pass -> Confirm
            mock_input.side_effect = ['new_admin']
            mock_getpass.side_effect = ['newpassword456', 'supersecret789', 'supersecret789']
            
            with patch.object(sys, 'argv', ['vault', 'reset-password']):
                main()
                
            v = Vault(self.vault_file)
            self.assertTrue(v.unlock('new_admin', 'supersecret789'), "Reset password failed")

            # 7. SHOW PLAIN
            print("\n--- Testing SHOW-PLAIN ---")
            mock_input.side_effect = ['new_admin']
            mock_getpass.side_effect = ['supersecret789']
            
            with patch.object(sys, 'argv', ['vault', 'show-plain']):
                main()
                
            self.assertTrue(os.path.exists(self.plain_file), "Plain file not created")
            
            # 8. RESET CREDENTIALS (Recovery)
            print("\n--- Testing RESET-CREDENTIALS ---")
            # Confirm "yes" -> New User -> New Pass -> Confirm
            mock_input.side_effect = ['yes', 'recovered_user']
            mock_getpass.side_effect = ['recovered123', 'recovered123']
            
            with patch.object(sys, 'argv', ['vault', 'reset-credentials']):
                main()
                
            v = Vault(self.vault_file)
            self.assertTrue(v.unlock('recovered_user', 'recovered123'), "Recovered credentials failed")
            self.assertEqual(len(v.entries), 1) # Should recover the note
            self.assertEqual(v.entries[0]['title'], 'Test Note 1')

            print("\n--- ALL TESTS PASSED ---")
            
        except Exception as e:
            print(f"FAILED at step: {e}")
            raise

if __name__ == '__main__':
    unittest.main()
