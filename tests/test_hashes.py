# tests/test_entity_hash.py
import tempfile

import pytest
import hashlib
import random
from EntityHash import EntityHash


def generate_random_hash(seed: int) -> bytes:
    random.seed(seed)
    return random.randbytes(128)


@pytest.mark.parametrize("seed", [42, 43, 44, 45, 46])
def test_entity_hash(seed):
    random_data = generate_random_hash(seed)
    # Test FromHashlib
    sha256 = hashlib.sha256()
    sha256.update(random_data)
    entity_hash = EntityHash.FromHashlib(sha256)

    # Test FromBytes
    entity_hash_bytes = EntityHash.FromBytes(entity_hash.as_bytes)
    assert entity_hash_bytes.as_hex == sha256.hexdigest()

    # Test FromInt
    entity_hash_int = EntityHash.FromInt(entity_hash.as_int)
    assert entity_hash_int.as_hex == sha256.hexdigest()

    # Test FromHex
    entity_hash_hex = EntityHash.FromHex(entity_hash.as_hex)
    assert entity_hash_hex.as_hex == sha256.hexdigest()

    # Test FromBase64
    entity_hash_base64 = EntityHash.FromBase64(entity_hash.as_base64)
    assert entity_hash_base64.as_hex == sha256.hexdigest()


def test_file():
    random_data = random.randbytes(1024)
    tmp_file = tempfile.NamedTemporaryFile(delete=False)
    tmp_file.write(random_data)
    tmp_file.close()
    sha256 = hashlib.sha256()
    sha256.update(random_data)
    entity_hash = EntityHash.FromHashlib(sha256)

    entity_hash1 = EntityHash.FromDiskFile(tmp_file.name, "sha256")
    entity_hash2 = EntityHash.FromBytes(entity_hash.as_bytes)
    assert entity_hash1.as_hex == entity_hash2.as_hex


if __name__ == "__main__":
    for seed in [42, 43, 44, 45, 46]:
        test_entity_hash(seed)
    print("entity_hash tests passed")

    test_file()
    print("file tests passed")
