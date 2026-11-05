"""Strict hexadecimal helpers shared by the SM2 and SM4 modules."""

from __future__ import annotations

import re

_HEX_RE = re.compile(r"[0-9a-fA-F]*")


def _strip_prefix(text: str) -> str:
    return text[2:] if text[:2] in ("0x", "0X") else text


def bytes_to_hex(data: bytes) -> str:
    """Encode bytes as a lowercase hex string."""
    return data.hex()


def hex_to_bytes(text: str) -> bytes:
    """Decode a hex string, rejecting anything ``bytes.fromhex`` would tolerate."""
    digits = _strip_prefix(text)
    if len(digits) % 2 != 0 or not _HEX_RE.fullmatch(digits):
        raise ValueError("invalid hex string")
    return bytes.fromhex(digits)


def hex_to_int(text: str) -> int:
    """Parse a non-empty big-endian hex string as an integer."""
    digits = _strip_prefix(text)
    if not digits or not _HEX_RE.fullmatch(digits):
        raise ValueError("invalid hex string")
    return int(digits, 16)
