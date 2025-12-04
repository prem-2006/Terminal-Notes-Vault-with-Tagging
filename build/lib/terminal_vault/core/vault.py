import json
import os
import base64
import csv
import uuid
import datetime
from typing import Dict, List, Optional
from .security import derive_key, generate_salt, xor_bytes

class Vault:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.dat_file = filepath.replace('.json', '.dat')
        self.csv_file = filepath.replace('.json', '.csv')
        self.entries: List[Dict] = []
        self.salt: bytes = b''
        self.is_locked = True
        self.key: Optional[bytes] = None
        self.username: Optional[str] = None

    def create_new(self, username: str, password: str):
        self.salt = generate_salt()
        self.key = derive_key(password, self.salt)
        self.entries = []
        self.username = username
        self.is_locked = False
        self.save()

    def unlock(self, username: str, password: str) -> bool:
        if not os.path.exists(self.filepath):
            return False
        
        try:
            with open(self.filepath, 'r') as f:
                data = json.load(f)
            
            stored_username = data.get('username')
            if stored_username != username:
                return False

            salt_b64 = data.get('salt')
            if not salt_b64:
                return False
            self.salt = base64.b64decode(salt_b64)
            
            # Derive key
            derived_key = derive_key(password, self.salt)
            
            # Try to decrypt
            encrypted_data_b64 = data.get('data')
            if not encrypted_data_b64:
                self.entries = []
                self.key = derived_key
                self.username = username
                self.is_locked = False
                return True

            encrypted_data = base64.b64decode(encrypted_data_b64)
            decrypted_json_bytes = xor_bytes(encrypted_data, derived_key)
            
            try:
                entries_data = json.loads(decrypted_json_bytes.decode('utf-8'))
                self.entries = entries_data
                self.key = derived_key
                self.username = username
                self.is_locked = False
                return True
            except (json.JSONDecodeError, UnicodeDecodeError):
                return False
                
        except Exception as e:
            print(f"Error unlocking vault: {e}")
            return False

    def lock(self):
        self.entries = []
        self.key = None
        self.username = None
        self.is_locked = True

    def save(self):
        if self.is_locked or self.key is None:
            raise RuntimeError("Vault is locked")
        
        # Prepare data
        # Ensure username is in all entries
        for entry in self.entries:
            entry['username'] = self.username

        json_bytes = json.dumps(self.entries).encode('utf-8')
        encrypted_data = xor_bytes(json_bytes, self.key)
        
        # 1. Save JSON (Metadata + Encrypted Blob) - Secure Storage
        data = {
            'username': self.username,
            'salt': base64.b64encode(self.salt).decode('ascii'),
            'data': base64.b64encode(encrypted_data).decode('ascii')
        }
        with open(self.filepath, 'w') as f:
            json.dump(data, f, indent=2)

        # 2. Save DAT (Pure Encrypted Blob)
        with open(self.dat_file, 'wb') as f:
            f.write(encrypted_data)

        # 3. Save CSV (Plain Text)
        with open(self.csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['username', 'title', 'tags', 'note', 'date', 'id'])
            for entry in self.entries:
                writer.writerow([
                    entry.get('username', ''),
                    entry.get('title', ''),
                    ','.join(entry.get('tags', [])),
                    entry.get('note', ''),
                    entry.get('date', ''),
                    entry.get('id', '')
                ])
        
        # 4. Save Plain JSON (Readable Backup) - DISABLED for security
        # plain_json_file = self.filepath.replace('.json', '_plain.json')
        # with open(plain_json_file, 'w') as f:
        #     json.dump(self.entries, f, indent=2)

    def add_entry(self, title: str, note: str, tags: List[str] = None):
        if self.is_locked:
            raise RuntimeError("Vault is locked")
        
        entry = {
            'id': str(uuid.uuid4()),
            'date': datetime.datetime.now().isoformat(),
            'title': title,
            'note': note,
            'tags': tags or []
        }
        self.entries.append(entry)

    def get_entries(self, tag_filter: str = None) -> List[Dict]:
        if self.is_locked:
            raise RuntimeError("Vault is locked")
        
        if tag_filter:
            return [e for e in self.entries if tag_filter in e.get('tags', [])]
        return self.entries

    def update_credentials(self, new_username: str, new_password: str):
        if self.is_locked:
            raise RuntimeError("Vault is locked")
        
        self.username = new_username
        self.salt = generate_salt()
        self.key = derive_key(new_password, self.salt)
        self.save()
