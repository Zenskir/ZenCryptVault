import os
import sys
import argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

MAGIC = b"ZCV1"          # 4 bytes - identifies our file format
VERSION = b"\x01"        # 1 byte - format version
SALT_SIZE = 16           # bytes
NONCE_SIZE = 12          # bytes - standard for GCM
KEY_SIZE = 32            # 32 bytes = 256 bits for AES-256
PBKDF2_ITERATIONS = 200_000

# handles packing the header of the encrypted file and returns the bytes to be written to the file
def pack_header(salt, nonce):
  if len(salt) != SALT_SIZE:
      raise ValueError(f"Salt must be {SALT_SIZE} bytes, got {len(salt)}")
  if len(nonce) != NONCE_SIZE:
      raise ValueError(f"Nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")

  return MAGIC + VERSION + salt + nonce

# Handles parsing the header of the encrypted file and returns the salt and nonce for key derivation and decryption
def parse_header(data):
  if len(data) < len(MAGIC) + len(VERSION) + SALT_SIZE + NONCE_SIZE:
      raise ValueError("Data is too short to contain a valid header")

  magic = data[:len(MAGIC)]
  version = data[len(MAGIC):len(MAGIC) + len(VERSION)]
  salt = data[len(MAGIC) + len(VERSION):len(MAGIC) + len(VERSION) + SALT_SIZE]
  nonce = data[len(MAGIC) + len(VERSION) + SALT_SIZE:len(MAGIC) + len(VERSION) + SALT_SIZE + NONCE_SIZE]
  ciphertext = data[len(MAGIC) + len(VERSION) + SALT_SIZE + NONCE_SIZE:]

  if magic != MAGIC:
      raise ValueError("Invalid file format")
  if version != VERSION:
      raise ValueError("Unsupported file version")

  return salt, nonce, ciphertext
