import argparse
import sys
import asyncio
import getpass
import os
import json
import csv
from ..core.vault import Vault
from ..core.config import Config
from ..utils.logging_utils import setup_logging
from ..utils.batch import import_csv, batch_check_entries
from ..core.security import calculate_entropy
from ..core.lockout import LockoutManager

def get_masked_input(prompt: str = "Password: ") -> str:
    """
    Reads a password with asterisk masking on Windows, falls back to getpass on others.
    """
    sys.stdout.write(prompt)
    sys.stdout.flush()

    if os.name == 'nt':
        import msvcrt
        password = []
        while True:
            ch = msvcrt.getch()
            if ch == b'\r' or ch == b'\n':
                sys.stdout.write('\n')
                break
            elif ch == b'\x08':  # Backspace
                if len(password) > 0:
                    sys.stdout.write('\b \b')
                    password.pop()
            elif ch == b'\x03': # Ctrl+C
                raise KeyboardInterrupt
            else:
                try:
                    char = ch.decode('utf-8')
                    password.append(char)
                    sys.stdout.write('*')
                    sys.stdout.flush()
                except UnicodeDecodeError:
                    pass
        return "".join(password)
    else:
        return getpass.getpass("")

def validate_password(password: str) -> bool:
    if len(password) < 8:
        print("Error: Password must be at least 8 characters long.")
        return False
    if not password.isalnum():
        print("Error: Password must be alphanumeric (letters and numbers only).")
        return False
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        print("Error: Password must contain both letters and numbers.")
        return False
    return True

def authenticate(vault, lockout_manager):
    is_locked, remaining = lockout_manager.is_locked_out()
    if is_locked:
        print(f"Account locked. Try again in {int(remaining // 60)} minutes.")
        sys.exit(1)

    attempts = 0
    while attempts < 3:
        username = input("Username: ")
        pwd = get_masked_input("Password: ")
        
        if vault.unlock(username, pwd):
            lockout_manager.reset()
            return True
        
        attempts += 1
        lockout_manager.record_failure()
        if attempts < 3:
            print(f"Invalid credentials. {3 - attempts} attempts remaining.")
    
    print("Too many failed attempts. Try again after 1 hour.")
    sys.exit(1)

def main():
    config = Config()
    logger = setup_logging(config.get('General', 'log_file'))
    vault_file = config.get('General', 'vault_file')
    vault = Vault(vault_file)
    lockout_manager = LockoutManager()

    # Cleanup plain file on startup
    plain_file = vault_file.replace('.json', '_plain.json')
    if os.path.exists(plain_file):
        try:
            os.remove(plain_file)
        except OSError as e:
            pass

    parser = argparse.ArgumentParser(description="Terminal Notes Vault")
    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # vault init
    subparsers.add_parser('init', help='Initialize a new vault')

    # vault user
    subparsers.add_parser('user', help='Manage user credentials')
    
    # vault reset-password
    subparsers.add_parser('reset-password', help='Reset password')

    # vault reset-credentials (NEW)
    subparsers.add_parser('reset-credentials', help='Reset credentials using backup')

    # vault add --title "..." --tags "..."
    add_parser = subparsers.add_parser('add', help='Add a new entry')
    add_parser.add_argument('--title', required=True, help='Title of the entry')
    add_parser.add_argument('--tags', help='Comma-separated tags')

    # vault get --tag "..." or --search "..."
    get_parser = subparsers.add_parser('get', help='Retrieve entries')
    get_parser.add_argument('--tag', help='Filter by tag')
    get_parser.add_argument('--search', help='Search by title')

    # vault check entries.csv
    check_parser = subparsers.add_parser('check', help='Batch check entries')
    check_parser.add_argument('file', help='CSV file to check')

    # vault report
    subparsers.add_parser('report', help='Generate a security report')

    # vault show-plain
    subparsers.add_parser('show-plain', help='Reveal vault content in plain text')

    args = parser.parse_args()

    if args.command == 'init':
        if os.path.exists(vault_file):
            print(f"Vault already exists at {vault_file}")
            sys.exit(1)
        
        username = input("Set Username: ")
        while True:
            pwd = get_masked_input("Set Master Password: ")
            if not validate_password(pwd):
                continue
            confirm = get_masked_input("Confirm Password: ")
            if pwd != confirm:
                print("Passwords do not match.")
                continue
            break
            
        vault.create_new(username, pwd)
        print(f"Vault initialized at {vault_file}")
        logger.info("Vault initialized")

    elif args.command == 'user':
        if not os.path.exists(vault_file):
            print("Vault not found. Creating new vault.")
            username = input("Set Username: ")
            while True:
                pwd = get_masked_input("Set Master Password: ")
                if not validate_password(pwd):
                    continue
                confirm = get_masked_input("Confirm Password: ")
                if pwd != confirm:
                    print("Passwords do not match.")
                    continue
                break
            vault.create_new(username, pwd)
            print(f"Vault initialized at {vault_file}")
            logger.info("Vault initialized via user command")
        else:
            print("Please login to update credentials.")
            authenticate(vault, lockout_manager)
            
            print("Login successful. Enter new credentials.")
            new_username = input("New Username: ")
            while True:
                new_pwd = get_masked_input("New Password: ")
                if not validate_password(new_pwd):
                    continue
                confirm = get_masked_input("Confirm New Password: ")
                if new_pwd != confirm:
                    print("Passwords do not match.")
                    continue
                break
            
            vault.update_credentials(new_username, new_pwd)
            print("Credentials updated successfully.")
            logger.info("Credentials updated")

    elif args.command == 'reset-password':
        if not os.path.exists(vault_file):
            print("Vault not found.")
            sys.exit(1)
            
        print("Please login to reset password.")
        authenticate(vault, lockout_manager)
            
        print("Login successful. Enter new password.")
        while True:
            new_pwd = get_masked_input("New Password: ")
            if not validate_password(new_pwd):
                continue
            confirm = get_masked_input("Confirm New Password: ")
            if new_pwd != confirm:
                print("Passwords do not match.")
                continue
            break
        
        vault.update_credentials(vault.username, new_pwd)
        print("Password reset successfully.")
        logger.info("Password reset")

    elif args.command == 'reset-credentials':
        csv_file = vault_file.replace('.json', '.csv')
        if not os.path.exists(csv_file):
            print(f"Error: Backup file '{csv_file}' not found. Cannot reset credentials.", file=sys.stderr)
            print("The reset function relies on the auto-generated CSV backup.", file=sys.stderr)
            return

        print("WARNING: This will overwrite your current encrypted vault with data from the CSV backup.")
        confirm_reset = input("Are you sure you want to proceed? (yes/no): ").lower()
        if confirm_reset != 'yes':
            print("Operation cancelled.")
            return

        try:
            new_username = input("Enter new username: ").strip()
            if not new_username:
                print("Username cannot be empty.", file=sys.stderr)
                return
            new_password = get_masked_input("Enter new password: ")
            confirm_pass = get_masked_input("Confirm password: ")

            if new_password != confirm_pass:
                print("Passwords do not match.", file=sys.stderr)
                return

            # Read backup data
            recovered_entries = []
            try:
                with open(csv_file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        entry = {
                            'id': row.get('id'),
                            'date': row.get('date'),
                            'title': row.get('title'),
                            'note': row.get('note'),
                            'tags': row.get('tags', '').split(',') if row.get('tags') else [],
                            'username': new_username
                        }
                        recovered_entries.append(entry)
                print(f"Read {len(recovered_entries)} entries from backup.")
            except Exception as e:
                print(f"Error reading backup file: {e}", file=sys.stderr)
                return

            vault.create_new(new_username, new_password)
            vault.entries = recovered_entries
            vault.save()
            lockout_manager.reset()
            print("Credentials reset successfully. Data restored from backup.")
            logger.info("Credentials reset from backup")
            
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return

    elif args.command == 'add':
        if not os.path.exists(vault_file):
            print("Vault not found. Run 'vault init' first.")
            sys.exit(1)

        authenticate(vault, lockout_manager)

        note = input("Note: ")
        tags = [t.strip() for t in args.tags.split(',')] if args.tags else []
        vault.add_entry(args.title, note, tags)
        vault.save()
        print("Entry added.")
        logger.info(f"Entry added: {args.title}")

    elif args.command == 'get':
        if not os.path.exists(vault_file):
            print("Vault not found. Run 'vault init' first.")
            sys.exit(1)

        authenticate(vault, lockout_manager)

        entries = vault.get_entries()
        found = []
        for e in entries:
            if args.tag and args.tag not in e.get('tags', []):
                continue
            if args.search:
                search_term = args.search.lower()
                title_match = search_term in e.get('title', '').lower()
                note_match = search_term in e.get('note', '').lower()
                if not (title_match or note_match):
                    continue
            found.append(e)

        if not found:
            print("No entries found.")
        else:
            print(f"Found {len(found)} entries:")
            for e in found:
                print(f"- {e['title']} (ID: {e['id']}, Date: {e['date']})")
                print(f"  Tags: {', '.join(e['tags'])}")
                print(f"  Note: {e['note']}")

    elif args.command == 'check':
        print(f"Processing {args.file}...")
        try:
            entries = import_csv(args.file)
            results = asyncio.run(batch_check_entries(entries))
            
            print(f"{'Title':<20} | {'Entropy':<10} | {'Strength':<10}")
            print("-" * 46)
            for res in results:
                print(f"{res.get('title', 'N/A'):<20} | {res.get('entropy', 0):<10.2f} | {res.get('strength', 'N/A'):<10}")
        except Exception as e:
            print(f"Error: {e}")

    elif args.command == 'report':
        if not os.path.exists(vault_file):
            print("Vault not found.")
            sys.exit(1)
            
        authenticate(vault, lockout_manager)
            
        entries = vault.get_entries()
        print(f"Vault Report for {vault_file}")
        print(f"Total Entries: {len(entries)}")
        
        weak_count = 0
        for e in entries:
            ent = calculate_entropy(e['note'])
            if ent < 40:
                weak_count += 1
        
        print(f"Weak Notes/Passwords: {weak_count}")
        if weak_count > 0:
            print("Recommendation: Rotate weak secrets.")

    elif args.command == 'show-plain':
        if not os.path.exists(vault_file):
            print("Vault not found.")
            sys.exit(1)
            
        authenticate(vault, lockout_manager)
        
        plain_file = vault_file.replace('.json', '_plain.json')
        entries = vault.get_entries()
        
        with open(plain_file, 'w') as f:
            json.dump(entries, f, indent=2)
            
        print(f"Vault content revealed in {plain_file}")
        print("WARNING: This file is unencrypted. It will be deleted next time you run the app.")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
