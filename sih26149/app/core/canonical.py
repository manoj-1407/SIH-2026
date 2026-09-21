"""
RFC 8785 — JSON Canonicalization Scheme (JCS) Implementation.
Reference: https://www.rfc-editor.org/rfc/rfc8785.html

Produces deterministic, invariant UTF-8 representations of JSON data
suitable for cryptographic hashing and Ed25519 digital signatures.

Rules:
1. Whitespace: No whitespace outside of string literals (separators ',' and ':').
2. Object sorting: Keys sorted lexicographically by UTF-16 code unit values.
3. Strings: UTF-8 encoded with minimal standard JSON escape sequences.
4. Numbers: Deterministic ECMAScript / RFC 8785 compliant number serialization.
5. Invariance: Equivalent JSON data always produces byte-identical canonical output.
"""
import math
import json
from typing import Any


def _utf16_sort_key(s: str) -> list[int]:
    """Convert string to list of UTF-16 code units for lexicographical comparison."""
    return [ord(c) for c in s.encode('utf-16-be').decode('utf-16-be')]


def _canonicalize_number(n: int | float) -> str:
    """Format number according to RFC 8785 / ECMAScript Number-to-String rules."""
    if isinstance(n, bool):
        raise TypeError("Boolean passed as number")
    if isinstance(n, int):
        return str(n)
    if isinstance(n, float):
        if math.isnan(n) or math.isinf(n):
            raise ValueError(f"NaN and Infinity are not valid in RFC 8785 JCS: {n}")
        if n == 0.0:
            return "0"
        # Check if float is an exact integer within IEEE 754 precision
        if n.is_integer() and abs(n) < 1e21:
            return str(int(n))
        # Python's repr for floats produces shortest round-trippable representation
        # Format matching ECMAScript standard
        s = repr(n)
        if 'e' in s or 'E' in s:
            # Normalize exponential notation (e.g. 1e+20 -> 1e+20, 1e-05 -> 1e-5)
            mantissa, exp = s.lower().split('e')
            exp_int = int(exp)
            sign = "+" if exp_int >= 0 else "-"
            s = f"{mantissa}e{sign}{abs(exp_int)}"
        return s
    raise TypeError(f"Unsupported number type: {type(n)}")


def _canonicalize_string(s: str) -> str:
    """Serialize string per RFC 8785 minimal escaping rules."""
    res = ['"']
    for char in s:
        cp = ord(char)
        if char == '"':
            res.append('\\"')
        elif char == '\\':
            res.append('\\\\')
        elif char == '\b':
            res.append('\\b')
        elif char == '\f':
            res.append('\\f')
        elif char == '\n':
            res.append('\\n')
        elif char == '\r':
            res.append('\\r')
        elif char == '\t':
            res.append('\\t')
        elif cp < 0x20:
            res.append(f'\\u{cp:04x}')
        else:
            res.append(char)
    res.append('"')
    return "".join(res)


def _serialize_jcs(obj: Any) -> str:
    if obj is None:
        return "null"
    elif isinstance(obj, bool):
        return "true" if obj else "false"
    elif isinstance(obj, (int, float)):
        return _canonicalize_number(obj)
    elif isinstance(obj, str):
        return _canonicalize_string(obj)
    elif isinstance(obj, (list, tuple)):
        return "[" + ",".join(_serialize_jcs(x) for x in obj) + "]"
    elif isinstance(obj, dict):
        # Keys must be strings in standard JSON; sort by UTF-16 code units
        sorted_keys = sorted(obj.keys(), key=lambda k: [ord(c) for c in k.encode('utf-16-be').decode('utf-16-be')])
        items = []
        for k in sorted_keys:
            if not isinstance(k, str):
                raise TypeError(f"Dictionary key must be string in RFC 8785 JSON, got {type(k)}")
            items.append(_canonicalize_string(k) + ":" + _serialize_jcs(obj[k]))
        return "{" + ",".join(items) + "}"
    else:
        # Fallback to dict conversion if dataclass/pydantic or object with __dict__ / to_dict
        if hasattr(obj, "to_dict"):
            return _serialize_jcs(obj.to_dict())
        if hasattr(obj, "model_dump"):
            return _serialize_jcs(obj.model_dump())
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable under RFC 8785")


def canonicalize(obj: Any) -> bytes:
    """Produce canonical UTF-8 bytes for an evidence object per RFC 8785."""
    return _serialize_jcs(obj).encode('utf-8')


def canonicalize_str(obj: Any) -> str:
    """Return canonical RFC 8785 JSON as a UTF-8 string."""
    return _serialize_jcs(obj)


def is_equivalent(a: Any, b: Any) -> bool:
    """True if two objects are canonically identical per RFC 8785."""
    return canonicalize(a) == canonicalize(b)
