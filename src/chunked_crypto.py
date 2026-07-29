# This file is another feauture for this encryption/decryption program where instead of
# reading an entire file into memory at once and encrpyting that content. We read in fixed-sized
# chunk/pieces and for every chunk a nonce will be generated (unique) and encrpyt that chunk individually
# then write each chunk's nonce, length, and ciphertext to the output file in sequence.

# Additional Info:
#   - This is very benificial for the performance of the whole program. Where we set a limit to these
#     chunks and read in only x amounts of data at each time instead of reading the whole thing.
#   - Overall this feature provides memory efficiency, GCM's data limits, Fault isolation, real-world
#     relevance
#   - This feature also takes into consideration the birthday paradox where can have two chunk having
#     having the same nonce, which will be prevented using a nonce counter

import os
from container_format import *
from crypto_core import derive_key, decrypt_file

# Main encryption logic for splitting the file into chunks and encrypting each separate chunk with
# a unique nonce while utilizing a nonce counter
def chunk_encryption(input_path, output_path, password=None, keyfile=None):
  salt = os.urandom(SALT_SIZE)

  if password:
    key = derive_key(password, salt)
  elif keyfile:
    key = decrypt_file(keyfile, salt)
  else:
    raise ValueError("Must provide either a password or a file containing a key")

  nonce_prefix = os.urandom(NONCE_PREFIX)
  aesgcm = AESGCM(key)

