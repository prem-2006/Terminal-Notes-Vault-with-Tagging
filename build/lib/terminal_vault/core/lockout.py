import json
import os
import time

LOCKOUT_FILE = '.vault_lockout'
MAX_ATTEMPTS = 3
LOCKOUT_DURATION = 3600  # 1 hour

class LockoutManager:
    def __init__(self, filepath=LOCKOUT_FILE):
        self.filepath = filepath

    def _load(self):
        if not os.path.exists(self.filepath):
            return {'attempts': 0, 'last_failed': 0}
        try:
            with open(self.filepath, 'r') as f:
                return json.load(f)
        except:
            return {'attempts': 0, 'last_failed': 0}

    def _save(self, data):
        with open(self.filepath, 'w') as f:
            json.dump(data, f)

    def is_locked_out(self):
        data = self._load()
        if data['attempts'] >= MAX_ATTEMPTS:
            elapsed = time.time() - data['last_failed']
            if elapsed < LOCKOUT_DURATION:
                return True, LOCKOUT_DURATION - elapsed
            else:
                # Lockout expired, reset
                self.reset()
        return False, 0

    def record_failure(self):
        data = self._load()
        data['attempts'] += 1
        data['last_failed'] = time.time()
        self._save(data)
        return data['attempts']

    def reset(self):
        if os.path.exists(self.filepath):
            os.remove(self.filepath)
