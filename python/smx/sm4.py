"""SM4 block cipher (GB/T 32907-2016) with CBC mode and PKCS#7 padding.

Speed comes from T-tables, which merge the S-box and the linear transform into
key- and data-indexed lookups, as the baseline's S-box already was. Cache-timing
caveat: every table index depends on secret data. Pure Python has no hardware or
bitsliced alternative, and the interpreter gives no timing guarantee anyway, so
do not rely on this module where an attacker can observe cache timing on the
same machine. The 16-bit tables used for bulk data make this exposure larger.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from struct import Struct

from .hexutil import bytes_to_hex, hex_to_bytes
from .sm3 import SM3

_MASK32 = 0xFFFFFFFF
_BLOCK_SIZE = 16
# Payload size from which building the 16-bit tables pays for itself.
_WIDE_TABLE_THRESHOLD = 64 * 1024

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
_iter_blocks = Struct(">4I").iter_unpack

_RoundKeys = tuple[tuple[int, int, int, int], ...]


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _byte_tables(linear) -> tuple[tuple[int, ...], ...]:
    """Tables mapping each input byte position through the S-box and ``linear``."""
    low = tuple(linear(s) for s in _SBOX)
    return (
        tuple(_rotl(v, 24) for v in low),
        tuple(_rotl(v, 16) for v in low),
        tuple(_rotl(v, 8) for v in low),
        low,
    )


_T0, _T1, _T2, _T3 = _byte_tables(
    lambda b: b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24)
)
_KEY_T0, _KEY_T1, _KEY_T2, _KEY_T3 = _byte_tables(
    lambda b: b ^ _rotl(b, 13) ^ _rotl(b, 23)
)

_wide_tables: tuple[tuple[int, ...], tuple[int, ...]] | None = None


def _get_wide_tables() -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Build the 16-bit tables (about 5 MB, about 10 ms) at the first bulk operation."""
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
    a ^= 0xA3B1BAC6
    b ^= 0x56AA3350
    c ^= 0x677D9197
    d ^= 0xB27022DC
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


def _group_round_keys(keys: Sequence[int]) -> _RoundKeys:
    return tuple(zip(*[iter(keys)] * 4))


def _crypt_block(block: bytes, round_keys: _RoundKeys) -> bytes:
    if len(block) != _BLOCK_SIZE:
        raise ValueError("block must be 16 bytes")
    t0, t1, t2, t3 = _T0, _T1, _T2, _T3
    a, b, c, d = _unpack_block(block)
    for k0, k1, k2, k3 in round_keys:
        x = b ^ c ^ d ^ k0
        a ^= t0[x >> 24] ^ t1[x >> 16 & 255] ^ t2[x >> 8 & 255] ^ t3[x & 255]
        x = c ^ d ^ a ^ k1
        b ^= t0[x >> 24] ^ t1[x >> 16 & 255] ^ t2[x >> 8 & 255] ^ t3[x & 255]
        x = d ^ a ^ b ^ k2
        c ^= t0[x >> 24] ^ t1[x >> 16 & 255] ^ t2[x >> 8 & 255] ^ t3[x & 255]
        x = a ^ b ^ c ^ k3
        d ^= t0[x >> 24] ^ t1[x >> 16 & 255] ^ t2[x >> 8 & 255] ^ t3[x & 255]
    return _pack_block(d, c, b, a)


def _crypt_words(
    blocks: Iterable[tuple[int, int, int, int]],
    round_keys: _RoundKeys,
    chain: tuple[int, int, int, int] | None,
) -> list[int]:
    """Run blocks through the byte tables; with ``chain`` (an IV) apply CBC encryption."""
    t0, t1, t2, t3 = _T0, _T1, _T2, _T3
    output: list[int] = []
    p0, p1, p2, p3 = chain or (0, 0, 0, 0)
    for a, b, c, d in blocks:
        a ^= p0
        b ^= p1
        c ^= p2
        d ^= p3
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


def _crypt_words_wide(
    blocks: Iterable[tuple[int, int, int, int]],
    round_keys: _RoundKeys,
    chain: tuple[int, int, int, int] | None,
) -> list[int]:
    """Same as :func:`_crypt_words` with the 16-bit tables, for bulk data."""
    high, low = _get_wide_tables()
    output: list[int] = []
    p0, p1, p2, p3 = chain or (0, 0, 0, 0)
    for a, b, c, d in blocks:
        a ^= p0
        b ^= p1
        c ^= p2
        d ^= p3
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


def _crypt_bytes(
    data: bytes, round_keys: _RoundKeys, chain: tuple[int, int, int, int] | None
) -> bytes:
    crypt = _crypt_words if len(data) < _WIDE_TABLE_THRESHOLD else _crypt_words_wide
    words = crypt(_iter_blocks(data), round_keys, chain)
    return Struct(f">{len(words)}I").pack(*words)


def _prepare_key(material: bytes) -> bytes:
    """Use 16-byte input directly; otherwise use the SM3 hex digest's first 16 chars.

    The hex digest is uppercase and taken as ASCII, matching every other
    language in this repository.
    """
    if len(material) == _BLOCK_SIZE:
        return bytes(material)
    return (
        SM3().update(material).finish().hash_hex_upper()[:_BLOCK_SIZE].encode("ascii")
    )


def pkcs7_pad(data: bytes) -> bytes:
    """Pad data to a multiple of the block size."""
    pad_length = _BLOCK_SIZE - len(data) % _BLOCK_SIZE
    return data + bytes([pad_length]) * pad_length


def pkcs7_unpad(data: bytes) -> bytes:
    """Remove and validate PKCS#7 padding; empty input stays empty."""
    if not data:
        return b""
    pad_length = data[-1]
    if pad_length == 0 or pad_length > _BLOCK_SIZE or pad_length > len(data):
        raise ValueError("invalid padding")
    if data[-pad_length:] != bytes([pad_length]) * pad_length:
        raise ValueError("invalid padding")
    return data[:-pad_length]


class SM4:
    """SM4-CBC cipher. Call :meth:`set_key` before encrypting or decrypting."""

    def __init__(self) -> None:
        self._encrypt_keys: _RoundKeys = ()
        self._decrypt_keys: _RoundKeys = ()
        self._iv = b""
        self._iv_words = (0, 0, 0, 0)

    def set_key(self, key: bytes, iv: bytes) -> None:
        """Set the key and IV; values that are not 16 bytes are derived via SM3."""
        keys = _expand_key(_prepare_key(key))
        self._encrypt_keys = _group_round_keys(keys)
        self._decrypt_keys = _group_round_keys(keys[::-1])
        self._iv = _prepare_key(iv)
        self._iv_words = _unpack_block(self._iv)

    def _require_key(self) -> None:
        if not self._encrypt_keys:
            raise ValueError("key not set")

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt one raw 16-byte block without chaining or padding."""
        self._require_key()
        return _crypt_block(block, self._encrypt_keys)

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt one raw 16-byte block without chaining or padding."""
        self._require_key()
        return _crypt_block(block, self._decrypt_keys)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string (UTF-8) and return lowercase hex ciphertext."""
        self._require_key()
        padded = pkcs7_pad(plaintext.encode("utf-8"))
        output = _crypt_bytes(padded, self._encrypt_keys, self._iv_words)
        return bytes_to_hex(output)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt hex ciphertext and return the UTF-8 plaintext.

        Raises ValueError on malformed hex, bad length, bad padding or
        plaintext that is not valid UTF-8.
        """
        self._require_key()
        data = hex_to_bytes(ciphertext)
        size = len(data)
        if size % _BLOCK_SIZE != 0:
            raise ValueError("invalid ciphertext length")
        if not size:
            return ""
        # CBC decryption: P[i] = D(C[i]) ^ C[i-1], one big XOR after the block loop.
        decrypted = _crypt_bytes(data, self._decrypt_keys, None)
        shifted = self._iv + data[:-_BLOCK_SIZE]
        plain = int.from_bytes(decrypted, "big") ^ int.from_bytes(shifted, "big")
        return pkcs7_unpad(plain.to_bytes(size, "big")).decode("utf-8")
