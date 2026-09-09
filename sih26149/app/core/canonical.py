"""
Canonical evidence representation.

Deterministic JSON: keys sorted recursively, no extra whitespace.
Same logical evidence object always produces same bytes.
This is what gets hashed and signed.
"""
import json
from typing import Any


def canonicalize(obj: Any) -> bytes:
    """Produce canonical UTF-8 bytes for an evidence object."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=True,
    ).encode('utf-8')


def canonicalize_str(obj: Any) -> str:
    """Return canonical JSON as string."""
    return canonicalize(obj).decode('utf-8')


def is_equivalent(a: Any, b: Any) -> bool:
    """True if two objects are canonically identical.
    Reformatted-but-identical evidence is not treated as tampered.
    """
    return canonicalize(a) == canonicalize(b)
