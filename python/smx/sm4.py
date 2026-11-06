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

**This SM4 uses table lookups and is not cache-timing resistant.** The key schedule,
CBC encryption, single blocks and short decryptions index T-tables (the S-box merged
with the linear transform) by key- and data-dependent bytes, as OpenSSL and
BouncyCastle do. An attacker who can observe cache timing on the same machine may
learn the key. Long CBC decryptions run many blocks in parallel through the Boolean
S-box circuit of :mod:`smx._sm4_core` instead, because that is faster there. The
``security`` branch of this repository has the variant without secret-indexed tables.
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
# Measured on x86_64 and Apple M2: from this many blocks, decrypting in parallel lanes
# beats the byte tables, and the 16-bit tables once those have been built.
_LANES_MIN_BLOCKS = 32
_LANES_MIN_BLOCKS_WIDE = 48
# Payload size from which building the 16-bit tables pays for itself.
_WIDE_TABLE_THRESHOLD = 32 * 1024
_BYTE_ONES = 0x01010101
# Added before multiplying, so that every round key has the same number of CPython
# digits. Multiplying a round key directly costs more for larger keys.
_ROUND_KEY_OFFSET = 1 << 32

# GB/T 32907-2016 S-box.
_SBOX = bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c05"
    "2b679a762abe04c3aa44132649860699"
    "9c4250f491ef987a33540b43edcfac62"
    "e4b31ca9c908e89580df94fa758f3fa6"
    "4707a7fcf37317ba83593c19e6854fa8"
    "686b81b27164da8bf8eb0f4b70569d35"
    "1e240e5e6358d1a225227c3b01217887"
    "d40046579fd327524c3602e7a0c4c89e"
    "eabf8ad240c738b5a3f7f2cef96115a1"
    "e0ae5da49b341a55ad933230f58cb1e3"
    "1df6e22e8266ca60c02923ab0d534e6f"
    "d5db3745defd8e2f03ff6a726d6c5b51"
    "8d1baf92bbddbc7f11d95c411f105ad8"
    "0ac13188a5cd7bbd2d74d012b8e5b4b0"
    "8969974a0c96777e65b9f109c56ec684"
    "18f07dec3adc4d2079ee5f3ed7cb3948"
)

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


def _rotl(x: int, n: int) -> int:
    return (x << n | x >> (32 - n)) & _MASK32


def _byte_tables(linear) -> tuple[tuple[int, ...], ...]:
    """T_i[x] = linear(S(x)) for x in byte i of the word (byte 0 is the highest)."""
    low = tuple(linear(s) for s in _SBOX)
    return (
        tuple(_rotl(v, 24) for v in low),
        tuple(_rotl(v, 16) for v in low),
        tuple(_rotl(v, 8) for v in low),
        low,
    )


# Round function tables, L(B) = B ^ B<<<2 ^ B<<<10 ^ B<<<18 ^ B<<<24.
_T0, _T1, _T2, _T3 = _byte_tables(
    lambda b: b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24)
)
# Key schedule tables, L'(B) = B ^ B<<<13 ^ B<<<23.
_KEY_T0, _KEY_T1, _KEY_T2, _KEY_T3 = _byte_tables(
    lambda b: b ^ _rotl(b, 13) ^ _rotl(b, 23)
)

_wide_tables: tuple[tuple[int, ...], tuple[int, ...]] | None = None


def _get_wide_tables() -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Build the 16-bit tables (about 5 MB, 5 to 10 ms) at the first bulk operation.

    ``high[x]`` covers the upper two bytes of a word and ``low[x]`` the lower two,
    so one round takes two lookups instead of four.
    """
    global _wide_tables
    tables = _wide_tables
    if tables is None:
        high = tuple(a ^ b for a in _T0 for b in _T1)
        low = tuple(a ^ b for a in _T2 for b in _T3)
        tables = _wide_tables = (high, low)
    return tables


def _expand_key(key: bytes) -> tuple[int, ...]:
    t0, t1, t2, t3 = _KEY_T0, _KEY_T1, _KEY_T2, _KEY_T3
    a, b, c, d = _unpack_block(key)
    a ^= _FK[0]
    b ^= _FK[1]
    c ^= _FK[2]
    d ^= _FK[3]
    keys: list[int] = []
    for ck0, ck1, ck2, ck3 in zip(*[iter(_CK)] * 4):
        x = b ^ c ^ d ^ ck0
        a ^= t0[x >> 24] ^ t1[x >> 16 & 255] ^ t2[x >> 8 & 255] ^ t3[x & 255]
        x = c ^ d ^ a ^ ck1
        b ^= t0[x >> 24] ^ t1[x >> 16 & 255] ^ t2[x >> 8 & 255] ^ t3[x & 255]
        x = d ^ a ^ b ^ ck2
        c ^= t0[x >> 24] ^ t1[x >> 16 & 255] ^ t2[x >> 8 & 255] ^ t3[x & 255]
        x = a ^ b ^ c ^ ck3
        d ^= t0[x >> 24] ^ t1[x >> 16 & 255] ^ t2[x >> 8 & 255] ^ t3[x & 255]
        keys += (a, b, c, d)
    return tuple(keys)


def _group_round_keys(keys) -> tuple[tuple[int, int, int, int], ...]:
    return tuple(zip(*[iter(keys)] * 4))


def _crypt_one(a, b, c, d, round_keys) -> tuple[int, int, int, int]:
    """Run one block given as four words and return the output words."""
    t0, t1, t2, t3 = _T0, _T1, _T2, _T3
    for k0, k1, k2, k3 in round_keys:
        x = b ^ c ^ d ^ k0
        a ^= t0[x >> 24] ^ t1[x >> 16 & 255] ^ t2[x >> 8 & 255] ^ t3[x & 255]
        x = c ^ d ^ a ^ k1
        b ^= t0[x >> 24] ^ t1[x >> 16 & 255] ^ t2[x >> 8 & 255] ^ t3[x & 255]
        x = d ^ a ^ b ^ k2
        c ^= t0[x >> 24] ^ t1[x >> 16 & 255] ^ t2[x >> 8 & 255] ^ t3[x & 255]
        x = a ^ b ^ c ^ k3
        d ^= t0[x >> 24] ^ t1[x >> 16 & 255] ^ t2[x >> 8 & 255] ^ t3[x & 255]
    return d, c, b, a


def _crypt_words(words, round_keys, chain) -> list[int]:
    """Run the blocks in ``words`` through the byte tables.

    With ``chain`` (the IV as four words) this is CBC encryption, otherwise ECB.
    """
    t0, t1, t2, t3 = _T0, _T1, _T2, _T3
    output: list[int] = []
    p0, p1, p2, p3 = chain or (0, 0, 0, 0)
    for i in range(0, len(words), 4):
        a = words[i] ^ p0
        b = words[i + 1] ^ p1
        c = words[i + 2] ^ p2
        d = words[i + 3] ^ p3
        for k0, k1, k2, k3 in round_keys:
            x = b ^ c ^ d ^ k0
            a ^= t0[x >> 24] ^ t1[x >> 16 & 255] ^ t2[x >> 8 & 255] ^ t3[x & 255]
            x = c ^ d ^ a ^ k1
            b ^= t0[x >> 24] ^ t1[x >> 16 & 255] ^ t2[x >> 8 & 255] ^ t3[x & 255]
            x = d ^ a ^ b ^ k2
            c ^= t0[x >> 24] ^ t1[x >> 16 & 255] ^ t2[x >> 8 & 255] ^ t3[x & 255]
            x = a ^ b ^ c ^ k3
            d ^= t0[x >> 24] ^ t1[x >> 16 & 255] ^ t2[x >> 8 & 255] ^ t3[x & 255]
        output += (d, c, b, a)
        if chain:
            p0, p1, p2, p3 = d, c, b, a
    return output


def _crypt_words_wide(words, round_keys, chain) -> list[int]:
    """Same as :func:`_crypt_words` with the 16-bit tables."""
    high, low = _get_wide_tables()
    output: list[int] = []
    p0, p1, p2, p3 = chain or (0, 0, 0, 0)
    for i in range(0, len(words), 4):
        a = words[i] ^ p0
        b = words[i + 1] ^ p1
        c = words[i + 2] ^ p2
        d = words[i + 3] ^ p3
        for k0, k1, k2, k3 in round_keys:
            x = b ^ c ^ d ^ k0
            a ^= high[x >> 16] ^ low[x & 0xFFFF]
            x = c ^ d ^ a ^ k1
            b ^= high[x >> 16] ^ low[x & 0xFFFF]
            x = d ^ a ^ b ^ k2
            c ^= high[x >> 16] ^ low[x & 0xFFFF]
            x = a ^ b ^ c ^ k3
            d ^= high[x >> 16] ^ low[x & 0xFFFF]
        output += (d, c, b, a)
        if chain:
            p0, p1, p2, p3 = d, c, b, a
    return output


def _crypt_bytes(data: bytes, round_keys, chain) -> bytes:
    """Run whole blocks through the tables, CBC-chained when ``chain`` is given.

    The 16-bit tables are used once they exist or the data is large enough to pay
    for building them.
    """
    words = Struct(f">{len(data) // 4}I").unpack(data)
    if _wide_tables is not None or len(data) >= _WIDE_TABLE_THRESHOLD:
        output = _crypt_words_wide(words, round_keys, chain)
    else:
        output = _crypt_words(words, round_keys, chain)
    return Struct(f">{len(output)}I").pack(*output)


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
    """Decrypt whole blocks without chaining.

    A few blocks go through the tables, more through the parallel lanes in batches.
    A short final batch goes through the tables too.
    """
    total = len(data) // _BLOCK_SIZE
    minimum = _LANES_MIN_BLOCKS if _wide_tables is None else _LANES_MIN_BLOCKS_WIDE
    if total < minimum:
        return _crypt_bytes(data, round_keys, None)
    parts = []
    for start in range(0, total, _BATCH_BLOCKS):
        lanes = min(_BATCH_BLOCKS, total - start)
        chunk = data[start * _BLOCK_SIZE : (start + lanes) * _BLOCK_SIZE]
        if lanes < minimum:
            parts.append(_crypt_bytes(chunk, round_keys, None))
        else:
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
        return bytes_to_hex(_crypt_bytes(padded, keys, _unpack_block(iv)))

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
