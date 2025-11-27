import argparse
import sys
import csv
import time
import json
import logging
from pathlib import Path
from typing import List
from .vault import Vault
from .security import InputMasker, AuditLogger, LoginThrottler

def main():
    parser = argparse.ArgumentParser(description="Terminal Notes Vault")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Init command
    subparsers.add_parser("init", help="Initialize a new vault")

    # Add command
    add_parser = subparsers.add_parser("add", help="Add a new entry")
    add_parser.add_argument("--title", help="Title of the entry")
    add_parser.add_argument("--tags", help="Comma-separated tags")

    # Get command
    get_parser = subparsers.add_parser("get", help="Retrieve entries")
    get_parser.add_argument("--tag", help="Filter by tag")
    get_parser.add_argument("--search", help="Search by title or tag")

    # Check command (Batch mode)
    check_parser = subparsers.add_parser("check", help="Batch check entries from CSV")
    check_parser.add_argument("file", help="CSV file to import/check")

    # Report command
    subparsers.add_parser("report", help="Generate a security report")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export decrypted vault to JSON")
    export_parser.add_argument("--file", help="Output JSON filename", default="vault_export.json")

    args = parser.parse_args()

    logger = AuditLogger()
    throttler = LoginThrottler()
    vault = Vault()

    # Check lockout before proceeding
    lockout_time = throttler.check_lockout()
    if lockout_time > 0:
        print(f"Locked out. Please wait {int(lockout_time)} seconds.")
        sys.exit(1)

    try:
        if args.command == "init":
            if vault.storage.exists():
                print("Vault already exists.")
                sys.exit(1)
            
            password = InputMasker.get_secret("Set new vault password: ")
            confirm = InputMasker.get_secret("Confirm password: ")
            
            if password != confirm:
                print("Passwords do not match.")
                sys.exit(1)
                
            vault.create_vault(password)
            print("Vault initialized successfully.")
            logger.log("Vault initialized.")

        elif args.command in ["add", "get", "check", "report", "export"]:
            if not vault.storage.exists():
                print("Vault not found. Run 'init' first.")
                sys.exit(1)

            # Authenticate
            attempts = 0
            while attempts < 3:
                password = InputMasker.get_secret("Enter vault password: ")
                try:
                    vault.unlock(password)
                    throttler.reset()
                    logger.log("Vault unlocked successfully.")
                    break
                except ValueError:
                    attempts += 1
                    throttler.record_failure()
                    print("Invalid password.")
                    logger.log("Failed login attempt.")
            
            if not vault.is_unlocked:
                print("Too many failed attempts.")
                sys.exit(1)

            # Execute command
            if args.command == "add":
                title = args.title or input("Title: ")
                secret = InputMasker.get_secret("Secret: ", hidden=False)
                tags = args.tags.split(",") if args.tags else input("Tags (comma-separated): ").split(",")
                tags = [t.strip() for t in tags if t.strip()]
                
                vault.add_entry(title, secret, tags)
                print("Entry added.")
                logger.log(f"Entry added: {title}")

            elif args.command == "get":
                if args.search:
                    entries = vault.search_entries(args.search)
                else:
                    entries = vault.get_entries(args.tag)
                
                if not entries:
                    print("No entries found.")
                else:
                    print(f"\nFound {len(entries)} entries:")
                    for entry in entries:
                        print(f"[{entry['title']}]")
                        print(f"  Tags: {', '.join(entry['tags'])}")
                        print(f"  Secret: {entry['secret']}")
                        print("-" * 20)
                logger.log(f"Entries retrieved. Count: {len(entries)}")

            elif args.command == "check":
                filepath = Path(args.file)
                if not filepath.exists():
                    print("File not found.")
                    sys.exit(1)
                
                count = 0
                with open(filepath, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        # Expecting 'title', 'secret', 'tags' columns
                        if 'title' in row and 'secret' in row:
                            tags = row.get('tags', '').split(',')
                            vault.add_entry(row['title'], row['secret'], [t.strip() for t in tags])
                            count += 1
                print(f"Batch imported {count} entries.")
                logger.log(f"Batch import: {count} entries.")

            elif args.command == "report":
                entries = vault.get_entries()
                print("\n=== Vault Security Report ===")
                print(f"Total Entries: {len(entries)}")
                print("Security metrics (entropy/strength) are no longer tracked.")
                logger.log("Security report generated.")

            elif args.command == "export":
                filename = args.file or "vault_export.json"
                entries = vault.get_entries()
                # Filter out entropy and strength from export
                export_entries = []
                for entry in entries:
                    clean_entry = entry.copy()
                    clean_entry.pop('entropy', None)
                    clean_entry.pop('strength', None)
                    export_entries.append(clean_entry)
                
                with open(filename, 'w') as f:
                    json.dump(export_entries, f, indent=2)
                print(f"Vault exported to {filename}")
                logger.log(f"Vault exported to {filename}")

        else:
            parser.print_help()

    except Exception as e:
        logger.log(f"Error: {str(e)}", level=logging.ERROR)
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
