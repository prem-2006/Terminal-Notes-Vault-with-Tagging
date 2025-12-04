# Terminal Notes Vault

A secure, terminal-based vault for storing notes and passwords with tagging support.
This project demonstrates secure coding practices using only Python standard libraries.

## Features

- **Secure Storage**: Uses PBKDF2 for key derivation and a demo XOR-based stream cipher (for demonstration purposes).
- **Tagging**: Organize entries with tags.
- **Batch Mode**: Import and check entries from CSV files.
- **Security Controls**:
    - Secure input masking.
    - Audit logging with redaction.
    - Brute-force protection (lockout after 3 failed attempts).
    - Password strength estimation.

## Installation

1. Clone the repository.
2. Install the package:
   ```bash
   pip install .
   ```

## Usage

### Initialize Vault
```bash
vault init
```

### Add Entry
```bash
vault add --title "My Secret" --tags "personal,finance"
```

### Retrieve Entries
```bash
vault get --tag "personal"
vault get --search "Secret"
```

### Batch Check
```bash
vault check entries.csv
```

### Generate Report
```bash
vault report
```

## Security Boundaries (Demo Scope)

> [!IMPORTANT]
> **Encryption**: This tool uses a **demonstration encryption scheme** (XOR stream cipher) because the requirements restricted usage to Python Standard Libraries only (no `cryptography` or `PyCryptodome`). **DO NOT USE FOR HIGH-VALUE SECRETS IN PRODUCTION.**

- **Key Derivation**: Uses `hashlib.pbkdf2_hmac` with SHA-256 and 100,000 iterations.
- **Memory Safety**: Python strings are immutable, so secrets may persist in memory until garbage collected.
- **Side Channels**: No specific protection against timing attacks or power analysis.

## Project Structure

- `src/`: Source code.
- `tests/`: Unit tests.
- `vault.log`: Audit log (redacted).
- `.vault_lockout`: Lockout state file.
