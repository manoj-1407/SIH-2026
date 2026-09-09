"""Unit tests for SHA-256 hashing."""
import os
import tempfile
import pytest
from app.core.hashing import hash_file, hash_bytes, hash_string, HashResult


def test_hash_bytes_known_value():
    """SHA-256 of empty string is known."""
    result = hash_bytes(b'')
    assert result == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


def test_hash_bytes_non_empty():
    result = hash_bytes(b'hello')
    assert len(result) == 64
    assert all(c in '0123456789abcdef' for c in result)


def test_hash_string():
    result = hash_string('hello')
    assert result == hash_bytes(b'hello')


def test_hash_file_temp(tmp_path):
    content = b'SIH26149 evidence content'
    f = tmp_path / 'test.bin'
    f.write_bytes(content)
    result = hash_file(str(f))
    assert isinstance(result, HashResult)
    assert result.hex_digest == hash_bytes(content)
    assert result.size_bytes == len(content)


def test_hash_file_empty(tmp_path):
    f = tmp_path / 'empty.bin'
    f.write_bytes(b'')
    result = hash_file(str(f))
    assert result.size_bytes == 0
    assert result.hex_digest == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


def test_hash_file_large(tmp_path):
    """Verify streaming: 5MB file hashed correctly."""
    content = os.urandom(5 * 1024 * 1024)
    f = tmp_path / 'large.bin'
    f.write_bytes(content)
    result = hash_file(str(f))
    assert result.size_bytes == 5 * 1024 * 1024
    assert result.hex_digest == hash_bytes(content)


def test_different_content_different_hash():
    h1 = hash_bytes(b'data_A')
    h2 = hash_bytes(b'data_B')
    assert h1 != h2
