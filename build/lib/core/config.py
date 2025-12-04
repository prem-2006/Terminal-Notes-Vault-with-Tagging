import configparser
import os

DEFAULT_CONFIG = {
    'General': {
        'vault_file': 'vault.json',
        'log_file': 'vault.log',
        'lockout_attempts': '3',
        'lockout_duration': '30'
    }
}

class Config:
    def __init__(self, config_file: str = 'config.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load()

    def load(self):
        if not os.path.exists(self.config_file):
            self.config.read_dict(DEFAULT_CONFIG)
            self.save()
        else:
            self.config.read(self.config_file)

    def save(self):
        with open(self.config_file, 'w') as f:
            self.config.write(f)

    def get(self, section, key, fallback=None):
        return self.config.get(section, key, fallback=fallback)
