# Instead of deriving a typed password, we have a file stored as random bytes
# where the files content will be derived to form the key. The process still applies
# where the key will passed into the PBKDF2 with the salt

import os
from container_format import *
from kdf import derive_key

# Generating the randomly order of bytes according to the size into a certain file
def generate_keyfile(path, size):
  generated_key = os.urandom(size)
  try:
    with open(path, 'wb') as fi:
      fi.write(generated_key)
  except OSError:
    raise ValueError("Path to file not working or some other issue occured")

# Taking the input of the bytes then feeding it into our derive_key function to create
# the specific key
def derive_keyfile(keyfile_path, salt):
  try:
    with open(keyfile_path, 'rb') as fi:
      key_bytes = fi.read()
  except OSError:
    raise ValueError("Could not open the path to the key file")

  return derive_key(key_bytes, salt)

