from src.crypto_core import *
from src.container_format import *

# Basic testing to ensure basic CLI functionality using the pytest library to ensure
# easier debugging tips
def test_basic_cli():
  # Setting up basic input data for calling the functions from crypto_core.py
  input_path="test_file_one.txt"
  output_path="test_file_one.zcv"
  decrypt_path="test_file_one.dec"
  sample_password="password123"
  text="Writing Secret Message Into The File"

  file = open(input_path, "w")
  file.write("Writing Secret Message Into The File")
  file.close()

  # Calling main functions
  encrypt_file(input_path, output_path, sample_password)
  decrypt_file(output_path, decrypt_path, sample_password)

  file = open(decrypt_path, 'r')
  info = file.read()
  file.close()

  # Ensures that original text file matches with the decrypted file
  assert text == info

  # Delete files for cleanup
  os.remove(input_path)
  os.remove(output_path)
  os.remove(decrypt_path)
