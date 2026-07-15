import pytest
from pathlib import Path

from src.crypto_core import *
from src.container_format import *

# Note: Claude was used for the edge cases to assist me with creating the specfic edge cases
#       to test the main function

SAMPLE_FILES_DIR = Path("sample_files")

@pytest.fixture(autouse=True)
def ensure_sample_dir():
    SAMPLE_FILES_DIR.mkdir(exist_ok=True)

def test_empty_file():
    empty_file = SAMPLE_FILES_DIR / "empty_file.txt"
    output_file = SAMPLE_FILES_DIR / "empty_file_output.dec"
    empty_file.touch()

    with pytest.raises(ValueError, match="Data is too short to contain a valid header"):
        decrypt_file(str(empty_file), str(output_file), "correct_password")

# def test_small_binary_file():
#     binary_file = SAMPLE_FILES_DIR / "small_binary_file.bin"
#     output_file = SAMPLE_FILES_DIR / "small_binary_output.dec"

#     # Needs to be long enough to pass the header length check,
#     # but with incorrect magic bytes so it fails format validation
#     binary_file.write_bytes(b"\x00" * 100)

#     with pytest.raises(ValueError, match="Invalid file format"):
#         decrypt_file(str(binary_file), str(output_file), "correct_password")

def test_too_short_file():
    """File shorter than the minimum header length."""
    short_file = SAMPLE_FILES_DIR / "short_file.bin"
    output_file = SAMPLE_FILES_DIR / "short_output.dec"
    short_file.write_bytes(b"\x00\x01\x02\x03")

    with pytest.raises(ValueError, match="Data is too short to contain a valid header"):
        decrypt_file(str(short_file), str(output_file), "correct_password")

def test_wrong_magic_bytes():
    """File long enough, but doesn't start with the correct magic bytes."""
    binary_file = SAMPLE_FILES_DIR / "wrong_magic.bin"
    output_file = SAMPLE_FILES_DIR / "wrong_magic_output.dec"
    binary_file.write_bytes(b"\x00" * 100)

    with pytest.raises(ValueError, match="Invalid file format"):
        decrypt_file(str(binary_file), str(output_file), "correct_password")

def test_wrong_password():
    plain_file = SAMPLE_FILES_DIR / "plain.txt"
    encrypted_file = SAMPLE_FILES_DIR / "valid_encrypted_file.zcv"
    output_file = SAMPLE_FILES_DIR / "wrong_password_output.dec"

    plain_file.write_text("Encrypted content")
    encrypt_file(str(plain_file), str(encrypted_file), "correct_password")

    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt_file(str(encrypted_file), str(output_file), "wrong_password")
