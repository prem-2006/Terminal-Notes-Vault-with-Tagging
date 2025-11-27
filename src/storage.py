import json
import os
import tempfile
from pathlib import Path
from typing import Dict, Any

class StorageHandler:
    """
    Handles secure file I/O for the vault.
    """
    def __init__(self, filepath: str = "my_vault.dat"):
        self.filepath = Path(filepath)

    def save(self, data: bytes):
        """
        Atomically saves data to the vault file.
        """
        # Write to a temporary file first
        dir_name = self.filepath.parent
        with tempfile.NamedTemporaryFile('wb', delete=False, dir=dir_name) as tmp_file:
            tmp_file.write(data)
            tmp_name = tmp_file.name
        
        # Atomically rename temporary file to target file
        os.replace(tmp_name, self.filepath)

    def load(self) -> bytes:
        """
        Loads data from the vault file.
        """
        if not self.filepath.exists():
            return b""
        
        with open(self.filepath, 'rb') as f:
            return f.read()

    def exists(self) -> bool:
        return self.filepath.exists()
