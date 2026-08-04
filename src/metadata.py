import json
from container_format import *

# Function prepares the metadata for encryption
def pack_metadata(filename):
  metadata = {
    "filename": filename
  }
  metadata_json = json.dumps(metadata).encode('utf-8')
  length_prefix = len(metadata_json).to_bytes(4, 'big')
  return length_prefix + metadata_json

def unpack_metadata(data):
    if len(data) < 4:
        raise ValueError("Corrupted data: missing metadata length field")

    metadata_length = int.from_bytes(data[:4], 'big')
    offset = 4

    if len(data) < offset + metadata_length:
        raise ValueError("Corrupted data: incomplete metadata block")

    metadata_json = data[offset:offset + metadata_length]
    metadata = json.loads(metadata_json.decode('utf-8'))
    offset += metadata_length

    original_content = data[offset:]

    return metadata, original_content

