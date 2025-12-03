import logging
import re

class RedactingFormatter(logging.Formatter):
    def __init__(self, patterns: list, fmt=None, datefmt=None, style='%'):
        super().__init__(fmt, datefmt, style)
        self.patterns = patterns

    def format(self, record):
        msg = super().format(record)
        for pattern in self.patterns:
            msg = re.sub(pattern, '***REDACTED***', msg)
        return msg

def setup_logging(log_file: str = 'vault.log'):
    # Patterns to redact: looks like a password or secret
    # This is a heuristic.
    patterns = [
        r'(?<=password=)[^\s]+',
        r'(?<=secret=)[^\s]+',
        r'(?<=key=)[^\s]+'
    ]
    
    logger = logging.getLogger('terminal_vault')
    logger.setLevel(logging.INFO)
    
    handler = logging.FileHandler(log_file)
    formatter = RedactingFormatter(patterns, '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    return logger
