"""Unit tests for atomic evidence persistence."""
import os
import json
import threading
import tempfile
import pytest
from pathlib import Path
from app.core.persistence import (
    atomic_write_json, atomic_write_bytes,
    load_json, load_bytes, list_json_files, PersistenceError
)


def test_atomic_write_and_load(tmp_path):
    """Persistence test 1: basic write and read."""
    path = tmp_path / 'test.json'
    data = {'case_id': 'CASE-001', 'status': 'ACTIVE'}
    atomic_write_json(str(path), data)
    loaded = load_json(str(path))
    assert loaded == data


def test_no_tmp_files_remain(tmp_path):
    """Persistence test 2: no .tmp_ files remain after successful write."""
    path = tmp_path / 'evidence.json'
    atomic_write_json(str(path), {'x': 1})
    tmp_files = list(tmp_path.glob('.tmp_*'))
    assert tmp_files == []


def test_concurrent_writes_no_torn_read(tmp_path):
    """Persistence test 3: >200 concurrent writes, no torn reads."""
    path = tmp_path / 'concurrent.json'
    errors = []
    write_count = 200

    def writer(i):
        try:
            atomic_write_json(str(path), {'writer': i, 'payload': 'x' * 100})
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(write_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f'Write errors: {errors}'
    # Final file should be valid JSON (no torn read)
    result = load_json(str(path))
    assert 'writer' in result


def test_load_nonexistent_raises(tmp_path):
    """Persistence test 4: missing file raises PersistenceError."""
    with pytest.raises(PersistenceError):
        load_json(str(tmp_path / 'nonexistent.json'))


def test_load_corrupt_json_raises(tmp_path):
    """Interrupted write simulation — corrupt file raises."""
    path = tmp_path / 'corrupt.json'
    path.write_text('{not valid json{{')
    with pytest.raises(PersistenceError):
        load_json(str(path))


def test_atomic_write_bytes(tmp_path):
    path = tmp_path / 'evidence.bin'
    data = b'\x00\x01\x02\x03' * 100
    atomic_write_bytes(str(path), data)
    loaded = load_bytes(str(path))
    assert loaded == data


def test_list_json_files(tmp_path):
    """list_json_files skips .tmp_ files."""
    (tmp_path / 'a.json').write_text('{}')
    (tmp_path / 'b.json').write_text('{}')
    (tmp_path / '.tmp_partial.json').write_text('{}')
    (tmp_path / 'readme.txt').write_text('text')
    files = list_json_files(str(tmp_path))
    names = [f.name for f in files]
    assert 'a.json' in names
    assert 'b.json' in names
    assert '.tmp_partial.json' not in names
    assert 'readme.txt' not in names
