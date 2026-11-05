"""Strict hexadecimal and bytes helpers shared by the SM2, SM3 and SM4 modules."""

from __future__ import annotations

import re

_HEX_RE = re.compile(r"[0-9a-fA-F]*")


def as_bytes(data) -> bytes:
    """Return the bytes of a buffer object, whatever its element format or layout.

    Raises TypeError for anything else. ``bytes(data)`` is not used because it turns
    an integer into that many zero bytes.
    """
    if type(data) is bytes:
        return data
    return memoryview(data).tobytes()


def bytes_to_hex(data: bytes) -> str:
    """Encode bytes as a lowercase hex string."""
    return as_bytes(data).hex()


def hex_to_bytes(text: str) -> bytes:
    """Decode an even-length hex string; no prefix, whitespace or separators allowed."""
    if len(text) % 2 != 0 or not _HEX_RE.fullmatch(text):
        raise ValueError("invalid hex string")
    return bytes.fromhex(text)


def hex_to_int(text: str) -> int:
    """Parse a non-empty big-endian hex string as an integer; no prefix allowed."""
    if not text or not _HEX_RE.fullmatch(text):
        raise ValueError("invalid hex string")
    return int(text, 16)
