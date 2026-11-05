"""SM3 cryptographic hash (GB/T 32905-2016)."""

from __future__ import annotations

from struct import Struct

from ._sm3_core import compress_blocks
from .hexutil import bytes_to_hex_upper

_BLOCK_SIZE = 64
_MAX_MESSAGE_BYTES = 2**61 - 1  # the padded length field holds 64 bits
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
    """Incremental SM3 hash; the instance resets itself after :meth:`finish`.

    Call :meth:`finish` once per message and read the digest before the next update.
    Reading a digest that does not belong to the data fed so far raises ValueError, and
    so does a second :meth:`finish` with no :meth:`update` in between. To hash an empty
    message on a used instance, call ``update(b"")`` first.

    An instance holds mutable state, so do not share one between threads.
    """

    def __init__(self) -> None:
        self._state = _IV
        self._buffer = bytearray()
        self._length = 0
        self._digest = b""

    def update(self, data: bytes) -> SM3:
        """Feed bytes into the hash.

        Accepts any buffer object and counts its size in bytes. Raises ValueError
        beyond 2**61 - 1 bytes in total, leaving the hash state unchanged.
        """
        view = memoryview(data)
        if view.format != "B" or view.ndim != 1 or not view.contiguous:
            view = memoryview(view.tobytes())
        size = view.nbytes
        if self._length + size > _MAX_MESSAGE_BYTES:
            raise ValueError("message too long for SM3")
        self._length += size
        self._digest = b""
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
        if self._length + 1 > _MAX_MESSAGE_BYTES:
            raise ValueError("message too long for SM3")
        buffer = self._buffer
        buffer.append(value)
        self._length += 1
        self._digest = b""
        if len(buffer) == _BLOCK_SIZE:
            self._state = compress_blocks(self._state, bytes(buffer))
            buffer.clear()
        return self

    def finish(self) -> SM3:
        """Apply padding, store the digest and reset for reuse."""
        if self._digest:
            raise ValueError("already finished; update before finishing again")
        self._digest = _finish_digest(self._state, bytes(self._buffer), self._length)
        self._buffer.clear()
        self._state = _IV
        self._length = 0
        return self

    def hash_bytes(self) -> bytes:
        """Return the 32-byte digest computed by the last :meth:`finish`."""
        if not self._digest:
            raise ValueError(
                "no digest: finish has not been called since the last update"
            )
        return self._digest

    def hash_hex_upper(self) -> str:
        """Return the last digest as an uppercase hex string."""
        return bytes_to_hex_upper(self.hash_bytes())
