"""SM3 cryptographic hash (GB/T 32905-2016)."""

from __future__ import annotations

_MASK32 = 0xFFFFFFFF
_BLOCK_SIZE = 64
_IV = (
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
)  # fmt: skip


def _rotl(x: int, n: int) -> int:
    n %= 32
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _p0(x: int) -> int:
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x: int) -> int:
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


# T_j <<< j, precomputed once for all 64 rounds.
_T = tuple(_rotl(0x79CC4519 if j < 16 else 0x7A879D8A, j) for j in range(64))


def _compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    w = [int.from_bytes(block[i : i + 4], "big") for i in range(0, _BLOCK_SIZE, 4)]
    for j in range(16, 68):
        w.append(
            _p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15))
            ^ _rotl(w[j - 13], 7)
            ^ w[j - 6]
        )

    a, b, c, d, e, f, g, h = state
    for j in range(64):
        a12 = _rotl(a, 12)
        ss1 = _rotl((a12 + e + _T[j]) & _MASK32, 7)
        ss2 = ss1 ^ a12
        if j < 16:
            ff = a ^ b ^ c
            gg = e ^ f ^ g
        else:
            ff = (a & b) | (a & c) | (b & c)
            gg = (e & f) | (~e & g & _MASK32)
        tt1 = (ff + d + ss2 + (w[j] ^ w[j + 4])) & _MASK32
        tt2 = (gg + h + ss1 + w[j]) & _MASK32
        a, b, c, d = tt1, a, _rotl(b, 9), c
        e, f, g, h = _p0(tt2), e, _rotl(f, 19), g

    return tuple(x ^ y for x, y in zip(state, (a, b, c, d, e, f, g, h)))


class SM3:
    """Incremental SM3 hash; the instance resets itself after :meth:`finish`."""

    def __init__(self) -> None:
        self._state = _IV
        self._buffer = bytearray()
        self._length = 0
        self._digest = b""

    def update(self, data: bytes) -> "SM3":
        """Feed bytes into the hash."""
        self._length += len(data)
        self._buffer += data
        full = len(self._buffer) - len(self._buffer) % _BLOCK_SIZE
        for offset in range(0, full, _BLOCK_SIZE):
            block = bytes(self._buffer[offset : offset + _BLOCK_SIZE])
            self._state = _compress(self._state, block)
        del self._buffer[:full]
        return self

    def update_byte(self, value: int) -> "SM3":
        """Feed a single byte (0-255) into the hash."""
        return self.update(bytes([value]))

    def finish(self) -> "SM3":
        """Apply padding, store the digest and reset for reuse."""
        bit_length = self._length * 8
        zeros = (55 - self._length) % _BLOCK_SIZE
        self.update(b"\x80" + bytes(zeros) + bit_length.to_bytes(8, "big"))
        self._digest = b"".join(word.to_bytes(4, "big") for word in self._state)
        self._state = _IV
        self._length = 0
        return self

    def hash_bytes(self) -> bytes:
        """Return the 32-byte digest computed by the last :meth:`finish`."""
        return self._digest

    def hash_hex_upper(self) -> str:
        """Return the last digest as an uppercase hex string."""
        return self._digest.hex().upper()
