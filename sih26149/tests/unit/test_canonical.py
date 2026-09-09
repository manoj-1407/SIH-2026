"""Unit tests for canonical evidence representation."""
import pytest
from app.core.canonical import canonicalize, canonicalize_str, is_equivalent


def test_sorted_keys():
    obj = {'z': 1, 'a': 2, 'm': 3}
    result = canonicalize_str(obj)
    assert result == '{"a":2,"m":3,"z":1}'


def test_no_whitespace():
    obj = {'key': 'value'}
    result = canonicalize_str(obj)
    assert ' ' not in result


def test_nested_sorted():
    obj = {'outer_z': {'inner_z': 1, 'inner_a': 2}, 'outer_a': 0}
    result = canonicalize_str(obj)
    # outer_a should come before outer_z
    assert result.index('outer_a') < result.index('outer_z')
    # inner_a should come before inner_z
    assert result.index('inner_a') < result.index('inner_z')


def test_same_object_same_bytes():
    """Same logical object always produces same bytes."""
    obj = {'case_id': 'CASE-001', 'result': 'VERIFIED', 'hash': 'abc123'}
    b1 = canonicalize(obj)
    b2 = canonicalize(obj)
    assert b1 == b2


def test_reformatted_is_equivalent():
    """Reformatted but identical content is not treated as tampered."""
    a = {'key': 'value', 'n': 42}
    b = {'n': 42, 'key': 'value'}  # different insertion order
    assert is_equivalent(a, b)


def test_changed_value_not_equivalent():
    a = {'classification': 'VERIFIED'}
    b = {'classification': 'INVALID'}
    assert not is_equivalent(a, b)


def test_changed_key_not_equivalent():
    a = {'hash': 'abc'}
    b = {'Hash': 'abc'}  # capital H
    assert not is_equivalent(a, b)


def test_returns_bytes():
    result = canonicalize({'x': 1})
    assert isinstance(result, bytes)


def test_utf8_encoding():
    """Result must be valid UTF-8."""
    result = canonicalize({'key': 'value'})
    assert result.decode('utf-8')
