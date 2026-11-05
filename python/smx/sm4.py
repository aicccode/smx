"""SM4 block cipher (GB/T 32907-2016) with CBC mode and PKCS#7 padding.

Security notes for callers:

- **CBC gives confidentiality only, with no integrity.** An attacker can change a
  ciphertext undetected, and any error a receiver reveals about a forged message can
  become a decryption oracle. Authenticate the ciphertext separately (encrypt then
  MAC, or a signature) and check that before calling :meth:`SM4.decrypt`.
- **The IV is fixed by** :meth:`SM4.set_key` **and every** :meth:`SM4.encrypt` **call
  reuses it**, so equal plaintexts give equal ciphertexts and a shared prefix shows.
  Call ``set_key`` with a fresh random IV for each message, and send the IV along.
- :meth:`SM4.encrypt_block` and :meth:`SM4.decrypt_block` are raw ECB building blocks.

The S-box is a Boolean circuit (see :mod:`smx._sm4_core`), so no table is indexed by
key or data. That removes the cache-timing channel of table lookups, at a large cost
for serial work: key schedule and CBC encryption. CBC decryption runs many blocks
through each gate at once and stays fast. CPython integers still take value-dependent
time at a very fine scale, so this is not a constant-time guarantee.
"""

from __future__ import annotations

from functools import lru_cache
from struct import Struct

from ._sm4_core import sub_bytes
from .hexutil import as_bytes, bytes_to_hex, lowercase_hex_to_bytes

_MASK32 = 0xFFFFFFFF
_BLOCK_SIZE = 16
_KEY_SIZE = 16
_BATCH_BLOCKS = 2048  # measured: larger batches gain little beyond this
_BYTE_ONES = 0x01010101
# Added before multiplying, so that every round key has the same number of CPython
# digits. Multiplying a round key directly costs more for larger keys.
_ROUND_KEY_OFFSET = 1 << 32

_FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)

_CK = (
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
)  # fmt: skip

_unpack_block = Struct(">4I").unpack
_pack_block = Struct(">4I").pack

_DECRYPT_ERROR = "decryption failed"


def _expand_key(key: bytes) -> tuple[int, ...]:
    a, b, c, d = _unpack_block(key)
    a ^= _FK[0]
    b ^= _FK[1]
    c ^= _FK[2]
    d ^= _FK[3]
    keys: list[int] = []
    for ck0, ck1, ck2, ck3 in zip(*[iter(_CK)] * 4):
        y = sub_bytes(b ^ c ^ d ^ ck0, _BYTE_ONES)
        a ^= y ^ (y << 13 & 0xFFFFE000 | y >> 19) ^ (y << 23 & 0xFF800000 | y >> 9)
        y = sub_bytes(c ^ d ^ a ^ ck1, _BYTE_ONES)
        b ^= y ^ (y << 13 & 0xFFFFE000 | y >> 19) ^ (y << 23 & 0xFF800000 | y >> 9)
        y = sub_bytes(d ^ a ^ b ^ ck2, _BYTE_ONES)
        c ^= y ^ (y << 13 & 0xFFFFE000 | y >> 19) ^ (y << 23 & 0xFF800000 | y >> 9)
        y = sub_bytes(a ^ b ^ c ^ ck3, _BYTE_ONES)
        d ^= y ^ (y << 13 & 0xFFFFE000 | y >> 19) ^ (y << 23 & 0xFF800000 | y >> 9)
        keys += (a, b, c, d)
    return tuple(keys)


def _group_round_keys(keys) -> tuple[tuple[int, int, int, int], ...]:
    return tuple(zip(*[iter(keys)] * 4))


def _crypt_one(a, b, c, d, round_keys) -> tuple[int, int, int, int]:
    """Run one block given as four words and return the output words."""
    ones = _BYTE_ONES
    for k0, k1, k2, k3 in round_keys:
        y = sub_bytes(b ^ c ^ d ^ k0, ones)
        a ^= (
            y
            ^ (y << 2 & 0xFFFFFFFC | y >> 30)
            ^ (y << 10 & 0xFFFFFC00 | y >> 22)
            ^ (y << 18 & 0xFFFC0000 | y >> 14)
            ^ (y << 24 & 0xFF000000 | y >> 8)
        )
        y = sub_bytes(c ^ d ^ a ^ k1, ones)
        b ^= (
            y
            ^ (y << 2 & 0xFFFFFFFC | y >> 30)
            ^ (y << 10 & 0xFFFFFC00 | y >> 22)
            ^ (y << 18 & 0xFFFC0000 | y >> 14)
            ^ (y << 24 & 0xFF000000 | y >> 8)
        )
        y = sub_bytes(d ^ a ^ b ^ k2, ones)
        c ^= (
            y
            ^ (y << 2 & 0xFFFFFFFC | y >> 30)
            ^ (y << 10 & 0xFFFFFC00 | y >> 22)
            ^ (y << 18 & 0xFFFC0000 | y >> 14)
            ^ (y << 24 & 0xFF000000 | y >> 8)
        )
        y = sub_bytes(a ^ b ^ c ^ k3, ones)
        d ^= (
            y
            ^ (y << 2 & 0xFFFFFFFC | y >> 30)
            ^ (y << 10 & 0xFFFFFC00 | y >> 22)
            ^ (y << 18 & 0xFFFC0000 | y >> 14)
            ^ (y << 24 & 0xFF000000 | y >> 8)
        )
    return d, c, b, a


@lru_cache(maxsize=8)
def _lane_masks(lanes: int) -> tuple[int, ...]:
    """Masks for ``lanes`` 32-bit words held in one integer (public, by batch size)."""
    repeat = ((1 << (32 * lanes)) - 1) // _MASK32
    return (
        repeat,
        _BYTE_ONES * repeat,
        *(
            part * repeat
            for rotation in (2, 10, 18, 24)
            for part in (_MASK32 << rotation & _MASK32, (1 << rotation) - 1)
        ),
    )


def _crypt_lanes(data: bytes, lanes: int, round_keys) -> bytes:
    """Run ``lanes`` independent blocks in parallel through every round.

    Column i of the blocks becomes one integer, so one gate of the S-box circuit
    works on every block. Rotations stay inside each 32-bit lane through masks.
    """
    repeat, ones, h2, l2, h10, l10, h18, l18, h24, l24 = _lane_masks(lanes)
    columns = []
    word_size = 4 * lanes
    for word in range(4):
        column = bytearray(word_size)
        for byte in range(4):
            column[byte::4] = data[4 * word + byte :: _BLOCK_SIZE]
        columns.append(int.from_bytes(column, "big"))
    a, b, c, d = columns
    offset = _ROUND_KEY_OFFSET
    removed = repeat << 32
    for k0, k1, k2, k3 in round_keys:
        y = sub_bytes(b ^ c ^ d ^ (k0 + offset) * repeat - removed, ones)
        a ^= (
            y
            ^ (y << 2 & h2 | y >> 30 & l2)
            ^ (y << 10 & h10 | y >> 22 & l10)
            ^ (y << 18 & h18 | y >> 14 & l18)
            ^ (y << 24 & h24 | y >> 8 & l24)
        )
        y = sub_bytes(c ^ d ^ a ^ (k1 + offset) * repeat - removed, ones)
        b ^= (
            y
            ^ (y << 2 & h2 | y >> 30 & l2)
            ^ (y << 10 & h10 | y >> 22 & l10)
            ^ (y << 18 & h18 | y >> 14 & l18)
            ^ (y << 24 & h24 | y >> 8 & l24)
        )
        y = sub_bytes(d ^ a ^ b ^ (k2 + offset) * repeat - removed, ones)
        c ^= (
            y
            ^ (y << 2 & h2 | y >> 30 & l2)
            ^ (y << 10 & h10 | y >> 22 & l10)
            ^ (y << 18 & h18 | y >> 14 & l18)
            ^ (y << 24 & h24 | y >> 8 & l24)
        )
        y = sub_bytes(a ^ b ^ c ^ (k3 + offset) * repeat - removed, ones)
        d ^= (
            y
            ^ (y << 2 & h2 | y >> 30 & l2)
            ^ (y << 10 & h10 | y >> 22 & l10)
            ^ (y << 18 & h18 | y >> 14 & l18)
            ^ (y << 24 & h24 | y >> 8 & l24)
        )
    output = bytearray(lanes * _BLOCK_SIZE)
    for word, column_value in enumerate((d, c, b, a)):
        column = column_value.to_bytes(word_size, "big")
        for byte in range(4):
            output[4 * word + byte :: _BLOCK_SIZE] = column[byte::4]
    return bytes(output)


def _decrypt_blocks(data: bytes, round_keys) -> bytes:
    """Decrypt whole blocks without chaining, in parallel batches."""
    total = len(data) // _BLOCK_SIZE
    if total == 1:
        return _pack_block(*_crypt_one(*_unpack_block(data), round_keys))
    parts = []
    for start in range(0, total, _BATCH_BLOCKS):
        lanes = min(_BATCH_BLOCKS, total - start)
        chunk = data[start * _BLOCK_SIZE : (start + lanes) * _BLOCK_SIZE]
        parts.append(_crypt_lanes(chunk, lanes, round_keys))
    return b"".join(parts)


def _require_16_bytes(value, name: str) -> bytes:
    """Return ``value`` as bytes if it is a buffer of exactly 16 bytes."""
    try:
        data = as_bytes(value)
    except TypeError:
        data = b""
    if len(data) != _KEY_SIZE:
        raise ValueError(f"{name} must be exactly 16 bytes")
    return data


def pkcs7_pad(data: bytes) -> bytes:
    """Pad data to a multiple of the block size."""
    data = as_bytes(data)
    pad_length = _BLOCK_SIZE - len(data) % _BLOCK_SIZE
    return data + bytes([pad_length]) * pad_length


def _padding_is_bad(data: bytes) -> int:
    """Return 1 if the non-empty data does not end in valid padding, else 0.

    This always reads the whole last block and has no branch on its content.
    """
    pad_length = data[-1]
    # Each term is 1 when its condition fails: pad_length is 0 or above the block size.
    bad = ((pad_length - 1) >> 8) & 1
    bad |= ((_BLOCK_SIZE - pad_length) >> 8) & 1
    for offset in range(1, _BLOCK_SIZE + 1):
        inside_padding = ((offset - pad_length - 1) >> 8) & 1
        differs = (((data[-offset] ^ pad_length) + 255) >> 8) & 1
        bad |= inside_padding & differs
    return bad


def pkcs7_unpad(data: bytes) -> bytes:
    """Remove and validate PKCS#7 padding; every failure raises the same ValueError."""
    data = as_bytes(data)
    size = len(data)
    if size == 0 or size % _BLOCK_SIZE != 0:
        raise ValueError(_DECRYPT_ERROR)
    if _padding_is_bad(data):
        raise ValueError(_DECRYPT_ERROR)
    return data[: -data[-1]]


def _decode_utf8(data: bytes) -> str | None:
    """Decode without letting an exception, which quotes the data, leave this frame."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


class SM4:
    """SM4-CBC cipher. Call :meth:`set_key` before encrypting or decrypting.

    See the module documentation: CBC has no integrity, and the IV stays the same for
    every :meth:`encrypt` until the next :meth:`set_key`.
    """

    def __init__(self) -> None:
        # Replaced as one object, so another thread sees an old or a new key and IV
        # together, never a mix of the two.
        self._keys: tuple = ()

    def set_key(self, key: bytes, iv: bytes) -> None:
        """Set the key and IV, each exactly 16 bytes; anything else raises ValueError."""
        key_bytes = _require_16_bytes(key, "key")
        iv_bytes = _require_16_bytes(iv, "iv")
        expanded = _expand_key(key_bytes)
        self._keys = (
            _group_round_keys(expanded),
            _group_round_keys(expanded[::-1]),
            iv_bytes,
        )

    def _require_key(self) -> tuple:
        keys = self._keys
        if not keys:
            raise ValueError("key not set")
        return keys

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt one raw 16-byte block without chaining or padding (ECB)."""
        keys = self._require_key()[0]
        data = _require_16_bytes(block, "block")
        return _pack_block(*_crypt_one(*_unpack_block(data), keys))

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt one raw 16-byte block without chaining or padding (ECB)."""
        keys = self._require_key()[1]
        data = _require_16_bytes(block, "block")
        return _pack_block(*_crypt_one(*_unpack_block(data), keys))

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string (UTF-8) and return lowercase hex ciphertext.

        CBC gives no integrity, and this reuses the IV of :meth:`set_key`.
        """
        keys, _, iv = self._require_key()
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be a string")
        try:
            encoded = plaintext.encode("utf-8")
        except UnicodeEncodeError:
            encoded = None
        if encoded is None:
            raise ValueError("plaintext is not valid text")
        padded = pkcs7_pad(encoded)
        p0, p1, p2, p3 = _unpack_block(iv)
        words = Struct(f">{len(padded) // 4}I").unpack(padded)
        output = []
        for offset in range(0, len(words), 4):
            p0, p1, p2, p3 = _crypt_one(
                words[offset] ^ p0,
                words[offset + 1] ^ p1,
                words[offset + 2] ^ p2,
                words[offset + 3] ^ p3,
                keys,
            )
            output += (p0, p1, p2, p3)
        return bytes_to_hex(Struct(f">{len(output)}I").pack(*output))

    def _decrypt_all(self, ciphertext: str) -> bytes | None:
        """Return all decrypted bytes, padding included, or None if malformed."""
        _, keys, iv = self._require_key()
        if not isinstance(ciphertext, str):
            raise TypeError("ciphertext must be a string")
        try:
            data = lowercase_hex_to_bytes(ciphertext)
        except ValueError:
            return None
        size = len(data)
        if size == 0 or size % _BLOCK_SIZE != 0:
            return None
        # CBC decryption: P[i] = D(C[i]) ^ C[i-1], one big XOR after the block loop.
        decrypted = _decrypt_blocks(data, keys)
        shifted = iv + data[:-_BLOCK_SIZE]
        plain = int.from_bytes(decrypted, "big") ^ int.from_bytes(shifted, "big")
        return plain.to_bytes(size, "big")

    def _decrypt_text(self, ciphertext: str) -> str | None:
        plain = self._decrypt_all(ciphertext)
        if plain is None:
            return None
        # The UTF-8 check runs on all the bytes whether or not the padding is valid, so
        # its duration cannot show which it was. Valid padding bytes are themselves
        # valid single-byte characters, so they do not change the outcome of the check.
        bad = _padding_is_bad(plain)
        text = _decode_utf8(plain)
        if bad or text is None:
            return None
        return text[: -plain[-1]]

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt lowercase hex ciphertext and return the UTF-8 plaintext.

        Malformed hex, uppercase hex, a bad length (including empty input), bad padding
        and plaintext that is not valid UTF-8 all raise the same ValueError.

        CBC gives no integrity, so authenticate the ciphertext first. UTF-8 checking
        runs on the same bytes with good and bad padding, but it stops at the first
        invalid byte, so its duration still depends on the content. If that matters, or
        the plaintext is binary, use :meth:`decrypt_bytes`, which has no UTF-8 step.
        """
        text = self._decrypt_text(ciphertext)
        if text is None:
            raise ValueError(_DECRYPT_ERROR)
        return text

    def _decrypt_bytes(self, ciphertext: str) -> bytes | None:
        plain = self._decrypt_all(ciphertext)
        if plain is None or _padding_is_bad(plain):
            return None
        return plain[: -plain[-1]]

    def decrypt_bytes(self, ciphertext: str) -> bytes:
        """Decrypt lowercase hex ciphertext and return the plaintext bytes.

        Everything that fails raises the same ValueError as :meth:`decrypt`.
        """
        data = self._decrypt_bytes(ciphertext)
        if data is None:
            raise ValueError(_DECRYPT_ERROR)
        return data

    def __reduce_ex__(self, protocol):
        raise TypeError("SM4 objects hold key material and cannot be pickled or copied")
