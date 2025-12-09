
import os
import sys
from unittest.mock import MagicMock, patch

# Path setup
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from terminal_vault.cli.main import main
from terminal_vault.core.vault import Vault


def debug_test():
    test_prefix = 'debug_full_suite'
    vault_file = f'{test_prefix}.json'
    csv_file = f'{test_prefix}.csv'
    dat_file = f'{test_prefix}.dat'
    plain_file = f'{test_prefix}_plain.json'
    log_file = 'debug_output.txt'

    # Cleanup
    for f in [vault_file, csv_file, dat_file, plain_file, log_file]:
        if os.path.exists(f): os.remove(f)

    # Redirect stdout to file
    original_stdout = sys.stdout
    log_f = open(log_file, 'w')
    sys.stdout = log_f
    
    def log(msg):
        # Write to file and flush
        log_f.write(str(msg) + "\n")
        log_f.flush()

    log(f"DEBUG: Starting test with vault_file={vault_file}")

    # Patches
    with patch('terminal_vault.cli.main.Config') as mock_config_cls, \
         patch('builtins.input') as mock_input, \
         patch('terminal_vault.cli.main.get_masked_input') as mock_getpass, \
         patch('sys.exit') as mock_exit:
        
        mock_config = mock_config_cls.return_value
        def config_side_effect(section, key, fallback=None):
            if key == 'vault_file': return vault_file
            if key == 'log_file': return 'debug_test.log'
            return fallback
        mock_config.get.side_effect = config_side_effect
        
        # Monitor exit
        def side_effect_exit(code=0):
            log(f"SYS_EXIT called with code {code}")
            if code != 0:
                raise SystemExit(code)
        mock_exit.side_effect = side_effect_exit

        try:
            # 1. INIT
            log("\n--- Testing INIT ---")
            mock_input.side_effect = ['admin']
            mock_getpass.side_effect = ['password123', 'password123']
            with patch.object(sys, 'argv', ['vault', 'init']):
                main()
            if not os.path.exists(vault_file): raise Exception("Init failed")

            # 2. ADD
            log("\n--- Testing ADD ---")
            mock_input.side_effect = ['admin', 'This is a test note'] 
            mock_getpass.side_effect = ['password123']
            with patch.object(sys, 'argv', ['vault', 'add', '--title', 'Test Note 1', '--tags', 'work,test']):
                main()

            # 3. GET
            log("\n--- Testing GET ---")
            mock_input.side_effect = ['admin']
            mock_getpass.side_effect = ['password123']
            with patch.object(sys, 'argv', ['vault', 'get', '--search', 'Test']):
                main()

            # 4. REPORT
            log("\n--- Testing REPORT ---")
            mock_input.side_effect = ['admin']
            mock_getpass.side_effect = ['password123']
            with patch.object(sys, 'argv', ['vault', 'report']):
                main()

            # 5. USER
            log("\n--- Testing USER ---")
            mock_input.side_effect = ['admin', 'new_admin']
            mock_getpass.side_effect = ['password123', 'newpassword456', 'newpassword456']
            with patch.object(sys, 'argv', ['vault', 'user']):
                main()

            # 6. RESET PASS
            log("\n--- Testing RESET-PASSWORD ---")
            mock_input.side_effect = ['new_admin']
            mock_getpass.side_effect = ['newpassword456', 'supersecret789', 'supersecret789']
            with patch.object(sys, 'argv', ['vault', 'reset-password']):
                main()

            # 7. SHOW PLAIN
            log("\n--- Testing SHOW-PLAIN ---")
            mock_input.side_effect = ['new_admin']
            mock_getpass.side_effect = ['supersecret789']
            with patch.object(sys, 'argv', ['vault', 'show-plain']):
                main()
            if not os.path.exists(plain_file): raise Exception("Show plain failed")

            # 8. RESET CREDENTIALS
            log("\n--- Testing RESET-CREDENTIALS ---")
            mock_input.side_effect = ['yes', 'recovered_user']
            mock_getpass.side_effect = ['recovered123', 'recovered123']
            with patch.object(sys, 'argv', ['vault', 'reset-credentials']):
                main()
            
            # Verify final state
            v = Vault(vault_file)
            if not v.unlock('recovered_user', 'recovered123'): raise Exception("Unlock failed after recovery")
            
            log("\nSUCCESS: All steps completed.")

        except SystemExit as e:
            log(f"\nCaught SystemExit: {e}")
        except Exception as e:
            log(f"\nCaught Exception: {e}")
            import traceback
            traceback.print_exc(file=log_f)
    
    sys.stdout = original_stdout
    log_f.close()


if __name__ == '__main__':
    debug_test()
