"""SM3 cryptographic hash (GB/T 32905-2016)."""

from __future__ import annotations

from struct import Struct

from ._sm3_core import compress_blocks

_BLOCK_SIZE = 64
_IV = (
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
)  # fmt: skip
_pack_digest = Struct(">8I").pack


def _finish_digest(state: tuple[int, ...], tail: bytes, total_length: int) -> bytes:
    """Pad the unabsorbed ``tail`` of a ``total_length``-byte message; return the digest."""
    zeros = (55 - total_length) % _BLOCK_SIZE
    padded = b"".join(
        (tail, b"\x80", bytes(zeros), (total_length * 8).to_bytes(8, "big"))
    )
    return _pack_digest(*compress_blocks(state, padded))


def _digest(data: bytes) -> bytes:
    """Return the SM3 digest of a complete message held in a bytes object."""
    size = len(data)
    full = size - size % _BLOCK_SIZE
    if not full:
        return _finish_digest(_IV, data, size)
    with memoryview(data) as view:
        state = compress_blocks(_IV, view[:full])
    return _finish_digest(state, data[full:], size)


class SM3:
    """Incremental SM3 hash; the instance resets itself after :meth:`finish`."""

    def __init__(self) -> None:
        self._state = _IV
        self._buffer = bytearray()
        self._length = 0
        self._digest = b""

    def update(self, data: bytes) -> SM3:
        """Feed bytes into the hash."""
        self._length += len(data)
        view = memoryview(data)
        if view.format != "B" or view.ndim != 1:
            view = view.cast("B")
        size = view.nbytes
        start = 0
        buffer = self._buffer
        if buffer:
            start = _BLOCK_SIZE - len(buffer)
            if size < start:
                buffer += view
                return self
            buffer += view[:start]
            self._state = compress_blocks(self._state, bytes(buffer))
            buffer.clear()
        end = size - (size - start) % _BLOCK_SIZE
        if end > start:
            self._state = compress_blocks(self._state, view[start:end])
        if end < size:
            buffer += view[end:]
        return self

    def update_byte(self, value: int) -> SM3:
        """Feed a single byte (0-255) into the hash."""
        buffer = self._buffer
        buffer.append(value)
        self._length += 1
        if len(buffer) == _BLOCK_SIZE:
            self._state = compress_blocks(self._state, bytes(buffer))
            buffer.clear()
        return self

    def finish(self) -> SM3:
        """Apply padding, store the digest and reset for reuse."""
        bit_length = self._length * 8
        zeros = (55 - self._length) % _BLOCK_SIZE
        self.update(b"\x80" + bytes(zeros) + bit_length.to_bytes(8, "big"))
        self._digest = _pack_digest(*self._state)
        self._state = _IV
        self._length = 0
        return self

    def hash_bytes(self) -> bytes:
        """Return the 32-byte digest computed by the last :meth:`finish`."""
        return self._digest

    def hash_hex_upper(self) -> str:
        """Return the last digest as an uppercase hex string."""
        return self._digest.hex().upper()
