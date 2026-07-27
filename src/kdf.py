from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from container_format import *

# password-based key derivation function using HMAC-SHA256 for deriving cryptographic keys from
# passwords or for securely storing passwords.
def derive_key(key, salt):
  if isinstance(key, str):
    key_material = key.encode('utf-8')
  else:
    key_material = key

  # Note that the salt is unique and randomly generated
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=KEY_SIZE,
    salt=salt,
    iterations=PBKDF2_ITERATIONS,
  )
  # Returns the key in the format of bytes and its length specified by the container format
  return kdf.derive(key_material)
