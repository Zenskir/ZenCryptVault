# The main CLI used to interact with the program and execute its designated functionalities

# Imported libraries
import argparse, sys, os
from crypto_core import encrypt_file, decrypt_file, derive_key
from keyfile import generate_keyfile, derive_keyfile
from container_format import *

# Main function
def main():
  # Splliting up the functionality using subparsers for each different functionality of this
  # program.
  parser = argparse.ArgumentParser(prog='ZenCryptVault', description='File encryption tool')
  subparsers = parser.add_subparsers(dest='command', required=True)

  #  Encryption Functionality
  encrpyt_parser = subparsers.add_parser('encrypt')
  encrpyt_parser.add_argument('input_file')
  encrpyt_parser.add_argument('-o', '--output', help='output file path')
  encrpyt_parser.add_argument('-p', '--password')
  encrpyt_parser.add_argument('-k', '--keyfile', help='path to file containing the key (alternate method to a password)')

  # Decryption Functionality
  decrypt_parser = subparsers.add_parser('decrypt')
  decrypt_parser.add_argument('input_file')
  decrypt_parser.add_argument('-o', '--output', help='output file path')
  decrypt_parser.add_argument('-p', '--password')
  decrypt_parser.add_argument('-k', '--keyfile', help='path to file containing the key (alternate method to a password)')

  generator_parser = subparsers.add_parser('generate-keyfile')
  generator_parser.add_argument('output_path')
  generator_parser.add_argument('-s', '--size', type=int, default=64)

  args = parser.parse_args()

  # Executing the command depending on the command provided
  if (args.command == 'encrypt'):
    if not args.password and not args.keyfile:
      parser.error("Must provide either --password or --keyfile")
    output = args.output or args.input_file + '.zcv'
    try:
     encrypt_file(args.input_file, output, password=args.password, keyfile=args.keyfile)
    except FileNotFoundError:
      print("Exception error occured: missing input files")
      sys.exit(1)
    except ValueError as e:
      print(f"Exception error occurred: {e}")
      sys.exit(1)
  elif (args.command == 'decrypt'):
    if not args.password and not args.keyfile:
      parser.error("Must provide either --password or --keyfile")
    output = args.output or args.input_file.replace('.zcv', '.dec')
    try:
      decrypt_file(args.input_file, output, password=args.password, keyfile=args.keyfile)
    except FileNotFoundError:
      print("Exception error occured: missing input files")
      sys.exit(1)
    except ValueError as e:
      print(f"Exception error occurred: {e}")
      sys.exit(1)
  elif (args.command == 'generate-keyfile'):
    if os.path.exists(args.output_path):
      validation = input(f'{args.output_path} already exists. Overwrite? (y/N): ')
      if (validation.lower() != 'y'):
        print('Aborted')
        return
    generate_keyfile(args.output_path, args.size)
    print(f"Keyfile generated at {args.output_path} ({args.size} bytes)")
    print("Keep this file safe — losing it means losing access to anything encrypted with it.")
    return

if __name__ == '__main__':
    main()
