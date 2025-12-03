import getpass
import sys
from ..core.vault import Vault
from ..core.security import calculate_entropy

class InteractiveSession:
    def __init__(self, vault_file, logger):
        self.vault = Vault(vault_file)
        self.logger = logger
        self.failed_attempts = 0
        self.last_failed_time = 0

    def start(self):
        print("Welcome to Terminal Notes Vault")
        while True:
            if self.vault.is_locked:
                self.login_menu()
            else:
                self.main_menu()

    def login_menu(self):
        print("\n1. Create New Vault")
        print("2. Unlock Vault")
        print("3. Exit")
        choice = input("Select: ")
        
        if choice == '1':
            pwd = getpass.getpass("Set Master Password: ")
            confirm = getpass.getpass("Confirm Password: ")
            if pwd == confirm:
                self.vault.create_new(pwd)
                print("Vault created and unlocked.")
                self.logger.info("New vault created")
            else:
                print("Passwords do not match.")
        elif choice == '2':
            if self.is_locked_out():
                print(f"Too many failed attempts. Try again later.")
                return

            pwd = getpass.getpass("Enter Master Password: ")
            if self.vault.unlock(pwd):
                print("Vault unlocked.")
                self.logger.info("Vault unlocked successfully")
                self.failed_attempts = 0
            else:
                print("Invalid password or vault not found.")
                self.logger.warning("Failed unlock attempt")
                self.handle_failed_attempt()
        elif choice == '3':
            sys.exit(0)

    def is_locked_out(self):
        # Simple in-memory lockout for this session
        # In a real app, this should persist or be system-wide
        if self.failed_attempts >= 3:
            import time
            if time.time() - self.last_failed_time < 30:
                return True
            else:
                self.failed_attempts = 0
        return False

    def handle_failed_attempt(self):
        import time
        self.failed_attempts += 1
        self.last_failed_time = time.time()
        if self.failed_attempts >= 3:
            print("Locked out for 30 seconds.")
            self.logger.warning("User locked out due to excessive failed attempts")

    def main_menu(self):
        print("\n--- Main Menu ---")
        print("1. Add Entry")
        print("2. List Entries")
        print("3. Lock & Exit")
        choice = input("Select: ")
        
        if choice == '1':
            title = input("Title: ")
            secret = getpass.getpass("Secret: ")
            tags = input("Tags (comma separated): ").split(',')
            tags = [t.strip() for t in tags if t.strip()]
            
            self.vault.add_entry(title, secret, tags)
            self.vault.save()
            print("Entry added.")
            self.logger.info(f"Entry added: {title}")
            
            # Show entropy feedback
            ent = calculate_entropy(secret)
            print(f"Secret Entropy: {ent:.2f}")
            
        elif choice == '2':
            tag_filter = input("Filter by tag (empty for all): ").strip()
            entries = self.vault.get_entries(tag_filter if tag_filter else None)
            print(f"\nFound {len(entries)} entries:")
            for i, e in enumerate(entries):
                print(f"{i+1}. {e['title']} (Tags: {', '.join(e['tags'])})")
                
            view = input("View entry # (or enter to skip): ")
            if view.isdigit():
                idx = int(view) - 1
                if 0 <= idx < len(entries):
                    print(f"Secret: {entries[idx]['secret']}")
                    
        elif choice == '3':
            self.vault.lock()
            print("Vault locked.")
            sys.exit(0)
