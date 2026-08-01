import os
import sys
import argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

MAGIC = b"ZCV1"          # 4 bytes - identifies our file format
VERSION = b"\x01"        # 1 byte - format version
SALT_SIZE = 16           # 16 bytes
NONCE_SIZE = 12          # 12 bytes - standard for GCM
KEY_SIZE = 32            # 32 bytes = 256 bits for AES-256
PBKDF2_ITERATIONS = 200_000
CHUNK_SIZE = 64 * 1024 # Chunk Size for parsing - 16 KB for a more practical convention
CHUNK_HEADER = 4 # 4 bytes
NONCE_PREFIX = 8 # 8 Bytes - for randomized prefix for the nonce (each time its run will be unique)


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

# We need to have a different type of packing and parsing mechanisms then the ones
# above since chunking data requires a different type of data management
def pack_chuncked_header(salt, nonce_prefix):
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must be {SALT_SIZE} bytes, got {len(salt)}")
    if len(nonce_prefix) != NONCE_PREFIX:
        raise ValueError(f"Nonce prefix must be {NONCE_PREFIX} bytes, got {len(nonce_prefix)}")

    return MAGIC + VERSION + salt + nonce_prefix

def parse_chunked_header(data):
    header_size = len(MAGIC) + len(VERSION) + SALT_SIZE + NONCE_PREFIX

    if len(data) < header_size:
        raise ValueError("Data is too short to contain a valid chunked header")

    magic = data[:len(MAGIC)]
    version = data[len(MAGIC):len(MAGIC) + len(VERSION)]
    salt = data[len(MAGIC) + len(VERSION):len(MAGIC) + len(VERSION) + SALT_SIZE]
    nonce_prefix = data[len(MAGIC) + len(VERSION) + SALT_SIZE : header_size]

    if magic != MAGIC:
        raise ValueError("Invalid file format")
    if version != VERSION:
        raise ValueError("Unsupported file version")

    remaining_data = data[header_size:]  # everything after the header, the chunks

    return salt, nonce_prefix, remaining_data
