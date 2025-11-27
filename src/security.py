import getpass
import logging
import re
import time
import json
import os
from pathlib import Path
from datetime import datetime, timedelta

class InputMasker:
    """
    Handles secure input masking.
    """
    @staticmethod
    def get_secret(prompt: str = "Password: ", hidden: bool = True) -> str:
        """
        Securely reads a password from the terminal.
        """
        if hidden:
            try:
                return getpass.getpass(prompt)
            except Exception as e:
                print(f"Warning: Could not mask input: {e}")
                return input(prompt)
        else:
            return input(prompt)

class AuditLogger:
    """
    Logger that redacts sensitive information.
    """
    def __init__(self, log_file: str = "vault.log"):
        self.logger = logging.getLogger("vault_audit")
        self.logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
        
        # Patterns to redact
        self.sensitive_patterns = [
            r"Password: \S+",
            r"Secret: \S+",
            r"Key: \S+"
        ]

    def log(self, message: str, level: int = logging.INFO):
        """
        Logs a message with sensitive data redacted.
        """
        redacted_message = message
        for pattern in self.sensitive_patterns:
            redacted_message = re.sub(pattern, "[REDACTED]", redacted_message)
        
        self.logger.log(level, redacted_message)

class LoginThrottler:
    """
    Manages lockout and back-off for failed login attempts.
    """
    def __init__(self, state_file: str = ".vault_lockout"):
        self.state_file = Path(state_file)
        self.max_attempts = 3
        self.lockout_duration = 60 # seconds
        self._load_state()

    def _load_state(self):
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    self.attempts = data.get('attempts', 0)
                    self.last_attempt = datetime.fromisoformat(data.get('last_attempt'))
            except (json.JSONDecodeError, ValueError):
                self.attempts = 0
                self.last_attempt = datetime.min
        else:
            self.attempts = 0
            self.last_attempt = datetime.min

    def _save_state(self):
        data = {
            'attempts': self.attempts,
            'last_attempt': self.last_attempt.isoformat()
        }
        with open(self.state_file, 'w') as f:
            json.dump(data, f)

    def check_lockout(self) -> float:
        """
        Checks if the user is currently locked out.
        Returns the remaining lockout time in seconds, or 0 if not locked out.
        """
        if self.attempts >= self.max_attempts:
            elapsed = (datetime.now() - self.last_attempt).total_seconds()
            if elapsed < self.lockout_duration:
                return self.lockout_duration - elapsed
            else:
                # Lockout expired, reset attempts
                self.reset()
        return 0

    def record_failure(self):
        """
        Records a failed login attempt.
        """
        self.attempts += 1
        self.last_attempt = datetime.now()
        self._save_state()

    def reset(self):
        """
        Resets the failure counter on successful login.
        """
        self.attempts = 0
        self.last_attempt = datetime.min
        self._save_state()
        if self.state_file.exists():
            os.remove(self.state_file)
