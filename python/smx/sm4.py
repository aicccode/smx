"""SM4 block cipher (GB/T 32907-2016) with CBC mode and PKCS#7 padding."""

from __future__ import annotations

from .hexutil import bytes_to_hex, hex_to_bytes
from .sm3 import SM3

_MASK32 = 0xFFFFFFFF
_BLOCK_SIZE = 16

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


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _tau(a: int) -> int:
    return int.from_bytes(bytes(_SBOX[b] for b in a.to_bytes(4, "big")), "big")


def _t(a: int) -> int:
    b = _tau(a)
    return b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24)


def _t_prime(a: int) -> int:
    b = _tau(a)
    return b ^ _rotl(b, 13) ^ _rotl(b, 23)


def _expand_key(key: bytes) -> tuple[int, ...]:
    k = [int.from_bytes(key[i * 4 : i * 4 + 4], "big") ^ _FK[i] for i in range(4)]
    for i in range(32):
        k.append(k[i] ^ _t_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ _CK[i]))
    return tuple(k[4:])


def _crypt_block(block: bytes, round_keys: tuple[int, ...]) -> bytes:
    if len(block) != _BLOCK_SIZE:
        raise ValueError("block must be 16 bytes")
    x = [int.from_bytes(block[i : i + 4], "big") for i in range(0, _BLOCK_SIZE, 4)]
    for i, rk in enumerate(round_keys):
        x.append(x[i] ^ _t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk))
    return b"".join(word.to_bytes(4, "big") for word in reversed(x[32:]))


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


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
        self._encrypt_keys: tuple[int, ...] = ()
        self._decrypt_keys: tuple[int, ...] = ()
        self._iv = b""

    def set_key(self, key: bytes, iv: bytes) -> None:
        """Set the key and IV; values that are not 16 bytes are derived via SM3."""
        self._encrypt_keys = _expand_key(_prepare_key(key))
        self._decrypt_keys = tuple(reversed(self._encrypt_keys))
        self._iv = _prepare_key(iv)

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
        previous = self._iv
        output = bytearray()
        for offset in range(0, len(padded), _BLOCK_SIZE):
            previous = self.encrypt_block(
                _xor(padded[offset : offset + _BLOCK_SIZE], previous)
            )
            output += previous
        return bytes_to_hex(bytes(output))

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt hex ciphertext and return the UTF-8 plaintext.

        Raises ValueError on malformed hex, bad length, bad padding or
        plaintext that is not valid UTF-8.
        """
        self._require_key()
        data = hex_to_bytes(ciphertext)
        if len(data) % _BLOCK_SIZE != 0:
            raise ValueError("invalid ciphertext length")
        previous = self._iv
        output = bytearray()
        for offset in range(0, len(data), _BLOCK_SIZE):
            block = data[offset : offset + _BLOCK_SIZE]
            output += _xor(self.decrypt_block(block), previous)
            previous = block
        return pkcs7_unpad(bytes(output)).decode("utf-8")
