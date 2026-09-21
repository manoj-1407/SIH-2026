"""
Unit tests for RFC 8785 JSON Canonicalization Scheme (JCS).
Verifies deterministic sorting, number serialization, string escaping,
and invariance properties.
"""
import pytest
from app.core.canonical import canonicalize, canonicalize_str, is_equivalent


def test_rfc8785_key_sorting():
    obj1 = {"z": 1, "a": 2, "m": 3}
    obj2 = {"a": 2, "m": 3, "z": 1}
    assert canonicalize_str(obj1) == '{"a":2,"m":3,"z":1}'
    assert canonicalize(obj1) == canonicalize(obj2)
    assert is_equivalent(obj1, obj2)


def test_rfc8785_nested_structures():
    data = {
        "case_id": "CASE-101",
        "artifacts": [
            {"offset": 2048, "type": "JPEG", "hash": "abc"},
            {"offset": 1024, "type": "PNG", "hash": "xyz"}
        ],
        "active": True,
        "null_val": None
    }
    canon = canonicalize_str(data)
    assert canon == '{"active":true,"artifacts":[{"hash":"abc","offset":2048,"type":"JPEG"},{"hash":"xyz","offset":1024,"type":"PNG"}],"case_id":"CASE-101","null_val":null}'


def test_rfc8785_string_escaping():
    data = {"quote": 'hello "world"', "newline": "line1\nline2", "tab": "col1\tcol2"}
    canon = canonicalize_str(data)
    assert canon == '{"newline":"line1\\nline2","quote":"hello \\"world\\"","tab":"col1\\tcol2"}'


def test_rfc8785_number_formatting():
    data = {"int": 42, "zero": 0, "float_exact": 100.0, "negative": -5}
    canon = canonicalize_str(data)
    assert canon == '{"float_exact":100,"int":42,"negative":-5,"zero":0}'


def test_rfc8785_nan_inf_rejected():
    with pytest.raises(ValueError):
        canonicalize({"val": float("nan")})
    with pytest.raises(ValueError):
        canonicalize({"val": float("inf")})
