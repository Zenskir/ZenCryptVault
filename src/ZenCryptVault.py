import argparse
from crypto_core import encrypt_file, decrypt_file


def main():
  # Splliting up the functionality using subparsers for each different functionality of this
  # program.
  parser = argparse.ArgumentParser(prog='ZenCryptVault', description='File encryption tool')
  subparsers = parser.add_subparsers(dest='command', required=True)

  #  Encryption Functionality
  encrpyt_parser = subparsers.add_parser('encrypt')
  encrpyt_parser.add_argument('input_file')
  encrpyt_parser.add_argument('-o', '--output', help='output file path')
  encrpyt_parser.add_argument('-p', '--password', required=True)

  # Decryption Functionality
  decrypt_parser = subparsers.add_parser('decrypt')
  decrypt_parser.add_argument('input_file')
  decrypt_parser.add_argument('-o', '--output', help='output file path')
  decrypt_parser.add_argument('-p', '--password', required=True)

  args = parser.parse_args()

  # Executing the command depending on the command provided
  if (args.command == 'encrypt'):
    output = args.output or args.input_file + '.zcv'
    encrypt_file(args.input_file, output, args.password)
  elif (args.command == 'decrypt'):
    output = args.output or args.input_file.replace('.zcv', '.dec')
    decrypt_file(args.input_file, output, args.password)

if __name__ == '__main__':
    main()
