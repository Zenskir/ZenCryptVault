# ZenCryptVault

A command-line file encryption and decryption tool built from the ground up using AES-256-GCM authenticated encryption. Unlike basic encryption scripts, ZenCryptVault uses a custom-designed file container format, supports both password- and keyfile-based key derivation, and includes a chunked encryption mode for handling large files efficiently.

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Setup](#setup)
- [Usage](#usage)
- [Command Reference](#command-reference)
- [How It Works](#how-it-works)
- [Security Notes](#security-notes)
- [Running Tests](#running-tests)
- [Roadmap](#roadmap)
- [License](#license)

## Features

- **AES-256-GCM authenticated encryption** - confidentiality and tamper detection in one step
- **Password or keyfile-based key derivation** - use a typed password or a random keyfile as your key source
- **Custom binary container format** - self-designed file layout with magic bytes and versioning
- **Chunked encryption mode** - stream large files in fixed-size chunks instead of loading them entirely into memory
- **PBKDF2 key derivation** - 200,000+ iterations to resist brute-force attacks
- **Clean CLI** - subcommands for encrypt, decrypt, chunked encrypt/decrypt, and keyfile generation

## Project Structure

```
ZenCryptVault/
├── src/
│   ├── ZenCryptVault.py     # CLI entry point
│   ├── crypto_core.py        # Core AES-GCM encrypt/decrypt logic
│   ├── chunked_crypto.py     # Chunked encryption/decryption for large files
│   ├── keyfile.py            # Keyfile generation and key derivation
│   ├── kdf.py                # Shared PBKDF2 key derivation function
│   ├── container_format.py   # File format constants and header pack/parse logic
│   └── metadata.py           # Encrypted metadata (original filename) handling
├── tests/                    # Automated test scripts
├── sample_files/              # Scratch files for manual testing
├── requirements.txt
├── .gitignore
└── README.md
```

## Requirements

- Python 3.9 or newer
- pip

## Setup

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd ZenCryptVault
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
```

### 3. Activate the virtual environment

**macOS / Linux:**
```bash
source venv/bin/activate
```

**Windows:**
```bash
venv\Scripts\activate
```

You'll need to reactivate this every time you open a new terminal session.

### 4. Upgrade pip

```bash
pip install --upgrade pip
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

This installs:
- **cryptography** - AES-GCM, PBKDF2, and related cryptographic primitives
- **tqdm** - progress bars for large file operations

## Usage

All commands are run from inside the `src/` directory:

```bash
cd src
```

### Encrypt a file (password)

```bash
python3 ZenCryptVault.py encrypt <input_file> -p <password> -o <output_file>
```

Example:
```bash
python3 ZenCryptVault.py encrypt secret.txt -p mypassword123 -o secret.zcv
```

### Decrypt a file (password)

```bash
python3 ZenCryptVault.py decrypt <input_file> -p <password> -o <output_file>
```

Example:
```bash
python3 ZenCryptVault.py decrypt secret.zcv -p mypassword123 -o secret_decrypted.txt
```

If `-o` is omitted, the tool will attempt to restore the original filename from the file's encrypted metadata.

### Generate a keyfile

Instead of a password, you can use a keyfile (a file filled with random bytes) as your key source.

```bash
python3 ZenCryptVault.py generate-keyfile <output_path> --size <bytes>
```

Example:
```bash
python3 ZenCryptVault.py generate-keyfile mykey.bin --size 64
```

**Keep this file safe.** Losing it means losing access to anything encrypted with it.

### Encrypt / decrypt with a keyfile

```bash
python3 ZenCryptVault.py encrypt secret.txt -k mykey.bin -o secret.zcv
python3 ZenCryptVault.py decrypt secret.zcv -k mykey.bin -o secret_decrypted.txt
```

### Chunked encryption (for large files)

Use `encrypt-chunk` / `decrypt-chunk` instead of `encrypt` / `decrypt` to process files in fixed-size chunks rather than loading the entire file into memory at once.

```bash
python3 ZenCryptVault.py encrypt-chunk bigfile.iso -k mykey.bin -o bigfile.zcv
python3 ZenCryptVault.py decrypt-chunk bigfile.zcv -k mykey.bin -o bigfile_decrypted.iso
```

**Note:** A file must be decrypted using the same mode (chunked or single-shot) it was encrypted with.

## Command Reference

| Command | Description |
|---|---|
| `encrypt <file> -p/-k <key> [-o <output>]` | Encrypt a file in single-shot mode |
| `decrypt <file> -p/-k <key> [-o <output>]` | Decrypt a file in single-shot mode |
| `encrypt-chunk <file> -p/-k <key> [-o <output>]` | Encrypt a file in chunked mode |
| `decrypt-chunk <file> -p/-k <key> [-o <output>]` | Decrypt a file in chunked mode |
| `generate-keyfile <path> [-s <size>]` | Generate a random keyfile |

**Flags:**
- `-o`, `--output` - output file path (optional; falls back to sensible defaults)
- `-p`, `--password` - password for key derivation
- `-k`, `--keyfile` - path to a keyfile for key derivation (alternative to `-p`)
- `-s`, `--size` - keyfile size in bytes (default: 64)

You must provide **either** `-p` or `-k` (not neither, and not required to provide both).

## How It Works

1. **Key derivation:** A password or keyfile is passed through PBKDF2-HMAC-SHA256 (200,000+ iterations) along with a randomly generated salt to produce a 256-bit key.
2. **Encryption:** The file contents are encrypted using AES-256-GCM with a randomly generated nonce, producing ciphertext plus a 16-byte authentication tag.
3. **Container format:** The output file is structured as:
   ```
   [MAGIC BYTES][VERSION][SALT][NONCE][CIPHERTEXT + TAG]
   ```
4. **Decryption:** The header is parsed to extract the salt and nonce, the key is re-derived, and the ciphertext is decrypted. If the password/keyfile is wrong or the file has been tampered with, the authentication tag check fails and decryption is rejected cleanly.

Chunked mode follows the same principles, but splits the file into fixed-size pieces (64KB by default), each encrypted with its own nonce derived from a per-chunk counter combined with a random per-file prefix - ensuring no nonce is ever reused under the same key.

## Security Notes

- The salt and nonce are **not secret** - they're stored in plaintext in the file header by design. Their purpose is uniqueness, not secrecy.
- Only the password/keyfile (and the key derived from it) are ever kept secret.
- This project was built as a learning exercise in applied cryptography and secure file format design. For protecting real sensitive data, use established, audited tools (e.g., GPG, VeraCrypt, age).

## Running Tests

```bash
cd tests
python3 test_round_trip.py
```

Or, with `pytest` installed:
```bash
pip install pytest
pytest tests/
```

## Roadmap

- [x] Core AES-GCM encryption/decryption
- [x] Custom container format
- [x] Password-based key derivation
- [x] Keyfile support
- [x] Chunked encryption for large files
- [ ] Encrypted metadata (original filename recovery)
- [ ] Multiple cipher support (ChaCha20-Poly1305)
- [ ] Envelope encryption (per-file data key + wrapping key)
- [ ] UI (TUI or GUI — exploring options)

## License

This project is for educational purposes.
