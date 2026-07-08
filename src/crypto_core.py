from container_format import *

# password-based key derivation function using HMAC-SHA256 for deriving cryptographic keys from
# passwords or for securely storing passwords.
def derive_key(password, salt):
  # Note that the salt is unique and randomly generated
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=KEY_SIZE,
    salt=salt,
    iterations=PBKDF2_ITERATIONS,
  )
  # Returns the key in the format of bytes and its length specified by the container format
  return kdf.derive(password.encode('utf-8'))

# Encrypts a file using AES-GCM with a password-derived key from calling the derive_key function. The builds and
# writes the header
def encrpt_file(input_path, output_path, password):
  # Generate a random salt and nonce
  salt = os.urandom(SALT_SIZE)
  nonce = os.urandom(NONCE_SIZE)

  # Derive the key from the password and salt
  key = derive_key(password, salt)

  # Read the input file
  with open(input_path, 'rb') as f:
    plaintext = f.read()

  # Encrypt the data using AES-GCM
  aesgcm = AESGCM(key)
  ciphertext = aesgcm.encrypt(nonce, plaintext, None)

  # Write the header and encrypted data to the output file
  with open(output_path, 'wb') as f:
    f.write(pack_header(salt, nonce))
    f.write(ciphertext)

# Handles reading the encrpyted file then parses the header and decrypts the data using AES-GCM with a password-derived key
# from calling the derive_key function.
def decrpyt_file(input_path, output_path, password):
  with open(input_path, 'rb') as f:
    data = f.read()

  salt, nonce, ciphertext = parse_header(data)
  # Derive the key from the password and salt
  key = derive_key(password, salt)

  # Decrypt the data using AES-GCM
  aesgcm = AESGCM(key)
  try:
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
  except InvalidTag:
    raise ValueError("Decryption failed. Invalid password or corrupted data.")

  # Write the decrypted data to the output file
  with open(output_path, 'wb') as f:
    f.write(plaintext)
