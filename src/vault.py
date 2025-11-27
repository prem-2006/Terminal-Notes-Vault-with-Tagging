import json
import uuid
from datetime import datetime
from typing import List, Dict, Optional
from .crypto_utils import derive_key, encrypt_data, decrypt_data
from .storage import StorageHandler

class Vault:
    """
    Main Vault class managing entries and encryption.
    """
    def __init__(self, filepath: str = "my_vault.dat"):
        self.storage = StorageHandler(filepath)
        self.entries: List[Dict] = []
        self.salt: bytes = None
        self.key: bytes = None
        self.is_unlocked = False

    def create_vault(self, password: str):
        """
        Initializes a new vault with the given password.
        """
        if self.storage.exists():
            raise FileExistsError("Vault already exists.")
        
        self.key, self.salt = derive_key(password)
        self.is_unlocked = True
        self._save()

    def unlock(self, password: str):
        """
        Unlocks an existing vault.
        """
        if not self.storage.exists():
            raise FileNotFoundError("Vault does not exist.")
        
        encrypted_blob = self.storage.load()
        
        # Extract salt (first 16 bytes)
        self.salt = encrypted_blob[:16]
        encrypted_data = encrypted_blob[16:]
        
        # Derive key
        self.key, _ = derive_key(password, self.salt)
        
        try:
            # Attempt decryption
            json_data = decrypt_data(encrypted_data, self.key)
            self.entries = json.loads(json_data)
            self.is_unlocked = True
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Invalid password or corrupted vault.")

    def add_entry(self, title: str, secret: str, tags: List[str] = None):
        """
        Adds a new entry to the vault.
        """
        if not self.is_unlocked:
            raise PermissionError("Vault is locked.")
        
        entry = {
            "id": str(uuid.uuid4()),
            "title": title,
            "secret": secret,
            "tags": tags or [],
            "created_at": datetime.now().isoformat()
        }
        self.entries.append(entry)
        self._save()

    def get_entries(self, tag_filter: str = None) -> List[Dict]:
        """
        Retrieves entries, optionally filtered by tag.
        """
        if not self.is_unlocked:
            raise PermissionError("Vault is locked.")
        
        if tag_filter:
            return [e for e in self.entries if tag_filter in e.get("tags", [])]
        return self.entries

    def search_entries(self, query: str) -> List[Dict]:
        """
        Searches entries by title or tags.
        """
        if not self.is_unlocked:
            raise PermissionError("Vault is locked.")
        
        query = query.lower()
        return [
            e for e in self.entries 
            if query in e["title"].lower() 
            or query in e["secret"].lower()
            or any(query in t.lower() for t in e.get("tags", []))
        ]

    def _save(self):
        """
        Encrypts and saves the current state.
        """
        if not self.key:
            raise ValueError("Vault not initialized.")
            
        json_data = json.dumps(self.entries)
        encrypted_data = encrypt_data(json_data, self.key)
        
        # Prepend salt to encrypted data
        blob = self.salt + encrypted_data
        self.storage.save(blob)
