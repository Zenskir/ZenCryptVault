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

# Layout:
# After a chunk is read and the ciphertext is produced. We take the length of the cipthertext and then
# add a 4-byte tag that will be allow the program to correctly read how much bytes the ciphertext is
# Example:
# Chunk 0 is full, and Chunk 1 has the remainder number of bytes
# [Chunk 0 Tag: 4-byte length][Chunk 0 Ciphertext][Chunk 1 Tag: 4-byte length][Chunk 1 Ciphertext]

import os
from container_format import *
from crypto_core import derive_key, decrypt_file
from keyfile import derive_keyfile
# Main encryption logic for splitting the file into chunks and encrypting each separate chunk with
# a unique nonce while utilizing a nonce counter
def chunk_encryption(input_path, output_path, password=None, keyfile=None):
  salt = os.urandom(SALT_SIZE)

  if password:
    key = derive_key(password, salt)
  elif keyfile:
    key = derive_keyfile(keyfile, salt)
  else:
    raise ValueError("Must provide either a password or a file containing a key")

  nonce_prefix = os.urandom(NONCE_PREFIX)
  aesgcm = AESGCM(key)

  with open(input_path, 'rb') as input_file,  open(output_path, 'wb') as output_file:
    output_file.write(pack_chuncked_header(salt, nonce_prefix))

    # chunk counter/index to keep track
    chunk_index = 0

    # Keep looping until all data from input_path (plain text data) are processed as a chunks
    while True:
      chunk = input_file.read(CHUNK_SIZE)
      if not chunk:
        break

      nonce = chunk_index.to_bytes(CHUNK_HEADER, 'big') + nonce_prefix
      ciphertext = aesgcm.encrypt(nonce, chunk, None)

      output_file.write(len(ciphertext).to_bytes(CHUNK_HEADER, 'big'))
      output_file.write(ciphertext)

      chunk_index += 1

# Function for reading in the encrypted file then parsing the neccessary data from the header
# to read in the chunks then decrypt each chunk's encrypted message then print it into the
# output file securly and accurately
def chunk_decryption(input_path, output_path, password=None, keyfile=None):
  with open(input_path, 'rb') as input_file, open(output_path, 'wb') as output_file:
    data = input_file.read()
    # parse the header from input_file to obtain neccessary data
    salt, nonce_prefix, chunks = parse_chunked_header(data)

    if password:
      key = derive_key(password, salt)
    elif keyfile:
      key = derive_keyfile(keyfile, salt)
    else:
      raise ValueError("Must provide either a password or a file containing a key")

    aesgcm = AESGCM(key)

    # Use offset to keep track of which chunk we are at and for error testing
    offset = 0
    chunk_index = 0

    while offset < len(chunks):
      length_bytes = chunks[offset:offset + CHUNK_HEADER]
      if len(length_bytes) < CHUNK_HEADER:
        raise ValueError("Corrupted file: incomplete chunk length field")
      chunk_length = int.from_bytes(length_bytes, 'big')
      offset += CHUNK_HEADER

      ciphertext = chunks[offset:offset + chunk_length]
      if len(ciphertext) < chunk_length:
        raise ValueError("Corrupted file: incomplete chunk data")
      offset += chunk_length

      nonce = chunk_index.to_bytes(CHUNK_HEADER, 'big') + nonce_prefix

      try:
        plaintext_chunk = aesgcm.decrypt(nonce, ciphertext, None)
      except InvalidTag:
        raise ValueError(f"Decryption failed at chunk {chunk_index}: invalid password/keyfile or corrupted data.")

      output_file.write(plaintext_chunk)
      chunk_index += 1




