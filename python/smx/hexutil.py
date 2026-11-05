"""Strict hexadecimal and bytes helpers shared by the SM2, SM3 and SM4 modules.

The conversions work on all characters at once with integer arithmetic, because some
of the values are secret and the usual routes (``bytes.hex``, ``bytes.fromhex``,
``int(text, 16)``, format strings, ``re``, ``str.upper``) look up each character in a
table inside CPython. The arithmetic below has no per-character branch or table in
Python code. It is not constant-time, as CPython integers give no such guarantee.
"""

from __future__ import annotations


def as_bytes(data) -> bytes:
    """Return the bytes of a buffer object, whatever its element format or layout.

    Raises TypeError for anything else. ``bytes(data)`` is not used because it turns
    an integer into that many zero bytes.
    """
    if type(data) is bytes:
        return data
    return memoryview(data).tobytes()


def _encode(data: bytes, letter_offset: int) -> str:
    """Encode bytes as hex; ``letter_offset`` is what takes "9" + 1 to the letter a."""
    size = len(data)
    if not size:
        return ""
    value = int.from_bytes(data, "big")
    low_nibbles = int.from_bytes(b"\x0f" * size, "big")
    nibbles = bytearray(2 * size)
    nibbles[0::2] = (value >> 4 & low_nibbles).to_bytes(size, "big")
    nibbles[1::2] = (value & low_nibbles).to_bytes(size, "big")
    digits = int.from_bytes(nibbles, "big")
    ones = int.from_bytes(b"\x01" * (2 * size), "big")
    # A nibble above 9 sets the top bit of its byte when 0x76 is added.
    is_letter = (digits + ones * 0x76) >> 7 & ones
    text = digits + ones * 0x30 + is_letter * letter_offset
    return text.to_bytes(2 * size, "big").decode("ascii")


def _decode(text: str, allow_uppercase: bool) -> bytes:
    """Decode an even-length string of hex digits; anything else raises ValueError."""
    if not text.isascii():
        raise ValueError("invalid hex string")
    raw = text.encode("ascii")
    size = len(raw)
    if not size:
        return b""
    chars = int.from_bytes(raw, "big")
    ones = int.from_bytes(b"\x01" * size, "big")
    high = ones * 0x80

    # For c below 0x80, the top bit of c + 0x80 - a says whether c >= a. No carry
    # crosses into the next byte.
    def at_least(bound: int) -> int:
        return (chars + ones * (0x80 - bound)) & high

    is_digit = at_least(0x30) & (at_least(0x3A) ^ high)
    is_letter = at_least(0x61) & (at_least(0x67) ^ high)
    if allow_uppercase:
        is_letter |= at_least(0x41) & (at_least(0x47) ^ high)
    if is_digit | is_letter != high:
        raise ValueError("invalid hex string")
    nibbles = ((chars & ones * 0x0F) + (is_letter >> 7) * 9).to_bytes(size, "big")
    high_part = int.from_bytes(nibbles[0::2], "big") << 4
    return (high_part | int.from_bytes(nibbles[1::2], "big")).to_bytes(size // 2, "big")


def bytes_to_hex(data: bytes) -> str:
    """Encode bytes as a lowercase hex string."""
    return _encode(as_bytes(data), 0x27)


def bytes_to_hex_upper(data: bytes) -> str:
    """Encode bytes as an uppercase hex string."""
    return _encode(as_bytes(data), 0x07)


def _require_even_text(text: str) -> None:
    if len(text) % 2 != 0:
        raise ValueError("invalid hex string")
    if not isinstance(text, str):
        raise TypeError("hex input must be a string")


def hex_to_bytes(text: str) -> bytes:
    """Decode an even-length hex string of either case; no prefix or separators."""
    _require_even_text(text)
    return _decode(text, True)


def lowercase_hex_to_bytes(text: str) -> bytes:
    """Decode the canonical lowercase hex that this library emits for signatures
    and ciphertexts, so each value has exactly one accepted spelling.
    """
    _require_even_text(text)
    return _decode(text, False)


def _digits_to_int(text: str, allow_uppercase: bool) -> int:
    if not isinstance(text, str):
        raise TypeError("hex input must be a string")
    if not text:
        raise ValueError("invalid hex string")
    padded = "0" + text if len(text) % 2 else text
    return int.from_bytes(_decode(padded, allow_uppercase), "big")


def hex_to_int(text: str) -> int:
    """Parse a non-empty big-endian hex string of either case; no prefix allowed."""
    return _digits_to_int(text, True)


def lowercase_hex_to_int(text: str) -> int:
    """Parse a non-empty big-endian lowercase hex string; no prefix allowed."""
    return _digits_to_int(text, False)
