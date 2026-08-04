from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from kdf import derive_key
from container_format import *
from keyfile import *
from metadata import pack_metadata, unpack_metadata


# Encrypts a file using AES-GCM with a password-derived key from calling the derive_key function. The builds and
# writes the header
# Refactor Note: Made changes to encrpyt_file after adding the feature of a keyfile, where the function
#                accepts the key as an argument instead of a password. Deriving logic will be done in
#                in main function.
def encrypt_file(input_path, output_path, password=None, keyfile=None):
  salt = os.urandom(SALT_SIZE)
  nonce = os.urandom(NONCE_SIZE)

  if keyfile:
        key = derive_keyfile(keyfile, salt)
  elif password:
        key = derive_key(password, salt)
  else:
        raise ValueError("Must provide either a password or a file containing a key")

  # Read the input file
  with open(input_path, 'rb') as f:
    plaintext = f.read()

  # prepare metadata for encryption - added addition for metadata functionalitity
  original_filename = os.path.basename(input_path)
  metadata_block = pack_metadata(original_filename)
  combined_data = metadata_block + plaintext

  # Encrypt the data using AES-GCM
  aesgcm = AESGCM(key)
  ciphertext = aesgcm.encrypt(nonce, combined_data, None)

  # Write the header and encrypted data to the output file
  with open(output_path, 'wb') as f:
    f.write(pack_header(salt, nonce))
    f.write(ciphertext)

# Handles reading the encrpyted file then parses the header and decrypts the data using AES-GCM with a password-derived key
# from calling the derive_key function.
# Refactor Note: Same thing applies here for the key file feature in encrpytion function
def decrypt_file(input_path, output_path=None, password=None, keyfile=None):
  with open(input_path, 'rb') as f:
    data = f.read()

  salt, nonce, ciphertext = parse_header(data)

  if keyfile:
    key = derive_keyfile(keyfile, salt)
  elif password:
    key = derive_key(password, salt)
  else:
    raise ValueError("Must provide either a password or a file containing a key")

  # Decrypt the data using AES-GCM
  aesgcm = AESGCM(key)
  try:
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
  except InvalidTag:
    raise ValueError("Decryption failed. Invalid password or corrupted data.")

  metadata, real_content = unpack_metadata(plaintext)

  if output_path is None:
     output_path = metadata.get("filename", "decrypted_output")

  # Write the decrypted data to the output file
  with open(output_path, 'wb') as f:
    f.write(real_content)

  return output_path
