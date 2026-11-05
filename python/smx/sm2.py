"""SM2 public key cryptography (GB/T 32918): encryption, signatures, key exchange.

Ciphertexts use the ``C1 || C3 || C2`` layout and signatures use ``r + "h" + s``,
both as lowercase hex, the same wire formats as the other languages here.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional

from . import _ec
from .hexutil import as_bytes, bytes_to_hex, hex_to_bytes, hex_to_int
from .point import SM2_A, SM2_B, SM2_GX, SM2_GY, SM2_N, ECPoint
from .sm3 import _BLOCK_SIZE, _IV, _digest, _finish_digest, compress_blocks

_C1_HEX_LEN = 130
_C3_HEX_LEN = 64
_HASH_SIZE = 32
_TWO_POW_W = 1 << 127
_W_MASK = _TWO_POW_W - 1
_TAG_SB = 0x02
_TAG_SA = 0x03
_PRIVATE_KEY_HEX_LEN = 64
_SIGNATURE_LEN = 129
_MAX_RETRIES = 128  # each retry has a negligible chance of being needed at all
_MAX_KDF_BYTES = (2**32 - 1) * _HASH_SIZE
_MAX_USER_ID_BYTES = 8191  # ENTL is the bit length in 16 bits
_MAX_EXCHANGE_KEY_BYTES = 1 << 20
_DECRYPT_ERROR = "decryption failed"
_Z_CURVE_PARAMETERS = b"".join(
    value.to_bytes(_HASH_SIZE, "big") for value in (SM2_A, SM2_B, SM2_GX, SM2_GY)
)
# Identities longer than this are hashed every time rather than kept in the cache.
_Z_CACHE_MAX_ID_LENGTH = 1024
_PUBLIC_KEY_CACHE_SIZE = 64
# Private key digest -> public key. Only public keys and one-way digests are kept,
# so the cache does not extend the lifetime of any secret value.
_public_key_cache: dict[bytes, ECPoint] = {}


@dataclass(frozen=True)
class SM2KeySwapParams:
    """Result of one side of the key exchange protocol."""

    sa: str = ""
    sb: str = ""
    # The shared keys and the shared point are secret, so repr() must not show them.
    ka: str = field(default="", repr=False)
    kb: str = field(default="", repr=False)
    # typing.get_type_hints() cannot evaluate "X | None" on Python 3.9.
    v: Optional[ECPoint] = field(default=None, repr=False)  # noqa: UP045
    za: bytes = b""
    zb: bytes = b""
    success: bool = False
    message: str = ""


def _random_scalar() -> int:
    """Return a uniform integer in [1, n-1] from the operating system CSPRNG.

    ``secrets.randbelow`` uses rejection sampling, so there is no modulo bias. A
    failing OS generator raises OSError, and no other source is ever tried.
    """
    return secrets.randbelow(SM2_N - 1) + 1


def _sm3(*parts: bytes) -> bytes:
    return _digest(b"".join(parts))


def _xor(left: bytes, right: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    value = int.from_bytes(left, "big") ^ int.from_bytes(right, "big")
    return value.to_bytes(len(left), "big")


def clear_key_caches() -> None:
    """Forget per-key cached values: Z values, public keys and point tables."""
    _cached_z.cache_clear()
    _public_key_cache.clear()
    _ec.clear_caches()


def set_key_cache_enabled(enabled: bool) -> None:
    """Turn the per-key caches on or off; turning them off also empties them.

    They start on unless the environment variable SMX_DISABLE_KEY_CACHE is set.
    """
    if not isinstance(enabled, bool):
        raise TypeError("enabled must be a bool")
    _ec.key_cache_enabled = enabled
    if not enabled:
        clear_key_caches()


def _encode_text(value: str, name: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    # The exception must not be raised inside the handler: UnicodeError keeps the
    # whole text and quotes part of it.
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        encoded = None
    if encoded is None:
        raise ValueError(f"{name} is not valid text")
    return encoded


def _encode_user_id(user_id: str) -> bytes:
    encoded = _encode_text(user_id, "user id")
    if len(encoded) > _MAX_USER_ID_BYTES:
        raise ValueError("user id too long")
    return encoded


def _parse_private_key(text: str) -> int:
    if not isinstance(text, str):
        raise TypeError("private key must be a hex string")
    if len(text) != _PRIVATE_KEY_HEX_LEN:
        raise ValueError("private key must be 64 hex digits")
    d = hex_to_int(text)
    if not 1 <= d <= SM2_N - 2:
        raise ValueError("private key out of range")
    return d


def _is_usable_public_point(point: ECPoint) -> bool:
    return isinstance(point, ECPoint) and point._is_valid_public()


def _is_private_scalar(value: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= SM2_N - 2
    )


def _kdf(key_length: int, seed_parts: Iterable[bytes]) -> bytes:
    """GB/T 32918.4 KDF: concatenate SM3(seed || counter) for counters 1, 2, ..."""
    if key_length > _MAX_KDF_BYTES:
        raise ValueError("KDF output too long")
    seed = b"".join(seed_parts)
    blocks = (key_length + _HASH_SIZE - 1) // _HASH_SIZE
    # Only the block holding the counter changes, so absorb the whole blocks once.
    full = len(seed) - len(seed) % _BLOCK_SIZE
    state = compress_blocks(_IV, seed[:full])
    tail = seed[full:]
    total = len(seed) + 4
    output = b"".join(
        [
            _finish_digest(state, tail + counter.to_bytes(4, "big"), total)
            for counter in range(1, blocks + 1)
        ]
    )
    return output[:key_length]


def user_sm3_z(user_id: bytes, public_key: ECPoint) -> bytes:
    """Compute Z = SM3(ENTL || ID || a || b || Gx || Gy || x || y)."""
    identity = as_bytes(user_id)
    if len(identity) > _MAX_USER_ID_BYTES:
        raise ValueError("user id too long")
    if not _is_usable_public_point(public_key):
        raise ValueError("invalid public key")
    x, y = public_key.x, public_key.y
    if not _ec.key_cache_enabled or len(identity) > _Z_CACHE_MAX_ID_LENGTH:
        return _compute_z(identity, x, y)
    z = _cached_z(identity, x, y)
    if not _ec.key_cache_enabled:  # disabled by another thread during the call
        _cached_z.cache_clear()
    return z


def _compute_z(user_id: bytes, x: int, y: int) -> bytes:
    entl = len(user_id) * 8  # at most 65528, as callers limit the length
    return _sm3(
        entl.to_bytes(2, "big"),
        user_id,
        _Z_CURVE_PARAMETERS,
        x.to_bytes(_HASH_SIZE, "big"),
        y.to_bytes(_HASH_SIZE, "big"),
    )


# Z takes four SM3 blocks and depends only on public values.
_cached_z = lru_cache(maxsize=256)(_compute_z)


def _public_key_of(d: int) -> ECPoint:
    """Return [d]G, remembering it under a digest of the private key."""
    if not _ec.key_cache_enabled:
        return ECPoint.generator().multiply(d)
    key = hashlib.sha256(d.to_bytes(_HASH_SIZE, "big")).digest()
    public_key = _public_key_cache.get(key)
    if public_key is None:
        public_key = ECPoint.generator().multiply(d)
        if len(_public_key_cache) >= _PUBLIC_KEY_CACHE_SIZE:
            _public_key_cache.clear()
        _public_key_cache[key] = public_key
        if not _ec.key_cache_enabled:  # disabled by another thread during the call
            _public_key_cache.clear()
    return public_key


def _message_digest(user_id: str, message: str, public_key: ECPoint) -> int:
    z = user_sm3_z(_encode_user_id(user_id), public_key)
    return int.from_bytes(_sm3(z, _encode_text(message, "message")), "big")


def sm2_gen_key_pair() -> tuple[str, str]:
    """Return ``(private_key_hex, public_key_hex)``; d is in [1, n-2]."""
    for _ in range(_MAX_RETRIES):
        d = _random_scalar()
        if d <= SM2_N - 2:
            return f"{d:064X}", ECPoint.generator().multiply(d).to_hex_encoded()
    raise ValueError("could not generate a key")


def sm2_encrypt(plaintext: str, public_key: str) -> str:
    """Encrypt a UTF-8 string and return ``C1 || C3 || C2`` as lowercase hex."""
    message = _encode_text(plaintext, "plaintext")
    if not message:
        raise ValueError("plaintext cannot be empty")
    if len(message) > _MAX_KDF_BYTES:
        raise ValueError("plaintext too long")

    # Decoding has already rejected anything that is not a usable public key.
    point = ECPoint.from_hex_encoded(public_key)

    for _ in range(_MAX_RETRIES):
        k = _random_scalar()
        c1 = ECPoint.generator().multiply(k)
        p2 = point._multiply_cached(k)
        if p2.infinity:
            continue

        key = _kdf(len(message), (p2.x_bytes(), p2.y_bytes()))
        if not any(key):
            continue

        c2 = _xor(message, key)
        c3 = _sm3(p2.x_bytes(), message, p2.y_bytes())
        return c1.to_hex_encoded() + bytes_to_hex(c3) + bytes_to_hex(c2)
    raise ValueError("encryption failed")


def sm2_decrypt(ciphertext: str, private_key: str) -> str:
    """Decrypt ``C1 || C3 || C2`` hex; raises ValueError if verification fails.

    Malformed input can raise different messages, but everything that depends on
    the private key raises the same one.
    """
    if not isinstance(ciphertext, str):
        raise TypeError("ciphertext must be a hex string")
    # C2 holds at least one byte, as encryption refuses an empty plaintext.
    if len(ciphertext) < _C1_HEX_LEN + _C3_HEX_LEN + 2 or len(ciphertext) % 2:
        raise ValueError("invalid ciphertext length")

    c1 = ECPoint.from_hex_encoded(ciphertext[:_C1_HEX_LEN])
    c3 = hex_to_bytes(ciphertext[_C1_HEX_LEN : _C1_HEX_LEN + _C3_HEX_LEN])
    c2 = hex_to_bytes(ciphertext[_C1_HEX_LEN + _C3_HEX_LEN :])
    if len(c2) > _MAX_KDF_BYTES:
        raise ValueError("invalid ciphertext length")

    p2 = c1.multiply(_parse_private_key(private_key))
    if p2.infinity:
        raise ValueError(_DECRYPT_ERROR)

    key = _kdf(len(c2), (p2.x_bytes(), p2.y_bytes()))
    if not any(key):
        raise ValueError(_DECRYPT_ERROR)
    message = _xor(c2, key)
    if not hmac.compare_digest(_sm3(p2.x_bytes(), message, p2.y_bytes()), c3):
        raise ValueError(_DECRYPT_ERROR)
    # The exception must not be raised inside the handler: it would keep the plaintext
    # in __context__, and its message quotes a plaintext byte.
    try:
        text = message.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None:
        raise ValueError(_DECRYPT_ERROR)
    return text


def sm2_sign(user_id: str, message: str, private_key: str) -> str:
    """Sign a message and return ``r + "h" + s`` as lowercase hex."""
    d = _parse_private_key(private_key)
    e = _message_digest(user_id, message, _public_key_of(d))
    d_plus_1_inv = _ec.invert_blinded(d + 1, SM2_N)

    for _ in range(_MAX_RETRIES):
        k = _random_scalar()
        x1 = ECPoint.generator().multiply(k).x
        r = (e + x1) % SM2_N
        if r == 0 or r + k == SM2_N:
            continue
        s = d_plus_1_inv * (k - r * d) % SM2_N
        if s == 0:
            continue
        return f"{r:064x}h{s:064x}"
    raise ValueError("signing failed")


def _parse_signature(signature: str) -> Optional[tuple[int, int]]:  # noqa: UP045
    if len(signature) != _SIGNATURE_LEN or signature[64] != "h":
        return None
    try:
        return hex_to_int(signature[:64]), hex_to_int(signature[65:])
    except ValueError:
        return None


def sm2_verify(user_id: str, signature: str, message: str, public_key: str) -> bool:
    """Verify a signature. Any invalid input of any kind returns False."""
    if not (
        isinstance(user_id, str)
        and isinstance(signature, str)
        and isinstance(message, str)
        and isinstance(public_key, str)
    ):
        return False
    parsed = _parse_signature(signature)
    if parsed is None:
        return False
    r, s = parsed
    if not (1 <= r < SM2_N and 1 <= s < SM2_N):
        return False

    t = (r + s) % SM2_N
    if t == 0:
        return False

    try:
        point = ECPoint.from_hex_encoded(public_key)
        e = _message_digest(user_id, message, point)
    except ValueError:
        return False
    result = _ec.to_affine_public(_ec.mul_shamir(s, t, point.x, point.y))
    if result is None:
        return False
    return (e + result[0]) % SM2_N == r


def _calc_x(x: int) -> int:
    return _TWO_POW_W + (x & _W_MASK)


def _calc_t(r: int, d: int, x_bar: int) -> int:
    return (d + x_bar * r) % SM2_N


def _calc_point(t: int, x_bar: int, p: ECPoint, r: ECPoint) -> ECPoint:
    # x_bar and both points are public. Only t is secret.
    scaled = _ec.mul_public(r.x, r.y, x_bar)
    base = _ec.to_affine_public(_ec.add_affine(scaled, p.x, p.y))
    return ECPoint._from_affine(base).multiply(t)


def _create_s(
    tag: int, vu: ECPoint, za: bytes, zb: bytes, r_a: ECPoint, r_b: ECPoint
) -> bytes:
    inner = _sm3(
        vu.x_bytes(), za, zb,
        r_a.x_bytes(), r_a.y_bytes(),
        r_b.x_bytes(), r_b.y_bytes(),
    )  # fmt: skip
    return _sm3(bytes([tag]), vu.y_bytes(), inner)


def _require_key_length(byte_len: int) -> None:
    if (
        not isinstance(byte_len, int)
        or isinstance(byte_len, bool)
        or not 1 <= byte_len <= _MAX_EXCHANGE_KEY_BYTES
    ):
        raise ValueError("key length must be between 1 and 1048576")


def _encode_ids(id_a: str, id_b: str) -> Optional[tuple[bytes, bytes]]:  # noqa: UP045
    try:
        return _encode_user_id(id_a), _encode_user_id(id_b)
    except (TypeError, ValueError):
        return None


def _is_hash_value(value: bytes) -> bool:
    return isinstance(value, (bytes, bytearray, memoryview)) and (
        len(as_bytes(value)) == _HASH_SIZE
    )


def sm2_get_sb(
    byte_len: int,
    p_a: ECPoint,
    r_a: ECPoint,
    p_b: ECPoint,
    d_b: int,
    r_b: ECPoint,
    rb: int,
    id_a: str,
    id_b: str,
) -> SM2KeySwapParams:
    """Compute responder B's shared key Kb and confirmation value Sb.

    A key length outside 1 to 1 MiB raises ValueError. Every other invalid input
    returns a result with ``success=False``.
    """
    _require_key_length(byte_len)
    if not _is_usable_public_point(p_a):
        return SM2KeySwapParams(message="PA point is not on curve")
    if not _is_usable_public_point(r_a):
        return SM2KeySwapParams(message="RA point is not on curve")
    if not _is_usable_public_point(p_b):
        return SM2KeySwapParams(message="PB point is not on curve")
    if not _is_usable_public_point(r_b):
        return SM2KeySwapParams(message="RB point is not on curve")
    if not (_is_private_scalar(d_b) and _is_private_scalar(rb)):
        return SM2KeySwapParams(message="private key out of range")
    ids = _encode_ids(id_a, id_b)
    if ids is None:
        return SM2KeySwapParams(message="invalid user id")

    tb = _calc_t(rb, d_b, _calc_x(r_b.x))
    v = _calc_point(tb, _calc_x(r_a.x), p_a, r_a)
    if v.infinity:
        return SM2KeySwapParams(message="V is point at infinity")

    za = user_sm3_z(ids[0], p_a)
    zb = user_sm3_z(ids[1], p_b)
    kb = _kdf(byte_len, (v.x_bytes(), v.y_bytes(), za, zb))
    sb = _create_s(_TAG_SB, v, za, zb, r_a, r_b)
    return SM2KeySwapParams(
        sb=bytes_to_hex(sb), kb=bytes_to_hex(kb), v=v, za=za, zb=zb, success=True
    )


def sm2_get_sa(
    byte_len: int,
    p_b: ECPoint,
    r_b: ECPoint,
    p_a: ECPoint,
    d_a: int,
    r_a: ECPoint,
    ra: int,
    id_a: str,
    id_b: str,
    sb: bytes,
) -> SM2KeySwapParams:
    """Verify B's Sb, then compute initiator A's shared key Ka and value Sa.

    A key length outside 1 to 1 MiB raises ValueError. Every other invalid input
    returns a result with ``success=False``.
    """
    _require_key_length(byte_len)
    if not _is_usable_public_point(p_b):
        return SM2KeySwapParams(message="PB point is not on curve")
    if not _is_usable_public_point(r_b):
        return SM2KeySwapParams(message="RB point is not on curve")
    if not _is_usable_public_point(p_a):
        return SM2KeySwapParams(message="PA point is not on curve")
    if not _is_usable_public_point(r_a):
        return SM2KeySwapParams(message="RA point is not on curve")
    if not (_is_private_scalar(d_a) and _is_private_scalar(ra)):
        return SM2KeySwapParams(message="private key out of range")
    ids = _encode_ids(id_a, id_b)
    if ids is None:
        return SM2KeySwapParams(message="invalid user id")
    if not _is_hash_value(sb):
        return SM2KeySwapParams(message="B's verification value does not match")

    ta = _calc_t(ra, d_a, _calc_x(r_a.x))
    u = _calc_point(ta, _calc_x(r_b.x), p_b, r_b)
    if u.infinity:
        return SM2KeySwapParams(message="U is point at infinity")

    za = user_sm3_z(ids[0], p_a)
    zb = user_sm3_z(ids[1], p_b)
    if not hmac.compare_digest(_create_s(_TAG_SB, u, za, zb, r_a, r_b), as_bytes(sb)):
        return SM2KeySwapParams(message="B's verification value does not match")

    ka = _kdf(byte_len, (u.x_bytes(), u.y_bytes(), za, zb))
    sa = _create_s(_TAG_SA, u, za, zb, r_a, r_b)
    return SM2KeySwapParams(sa=bytes_to_hex(sa), ka=bytes_to_hex(ka), success=True)


def sm2_check_sa(
    v: ECPoint, za: bytes, zb: bytes, r_a: ECPoint, r_b: ECPoint, sa: bytes
) -> bool:
    """Verify A's confirmation value Sa on B's side. Invalid input returns False."""
    if not (
        _is_usable_public_point(v)
        and _is_usable_public_point(r_a)
        and _is_usable_public_point(r_b)
        and _is_hash_value(za)
        and _is_hash_value(zb)
        and _is_hash_value(sa)
    ):
        return False
    expected = _create_s(_TAG_SA, v, as_bytes(za), as_bytes(zb), r_a, r_b)
    return hmac.compare_digest(expected, as_bytes(sa))


def sm2_decode_point(text: str) -> ECPoint:
    """Decode a ``04 || x || y`` hex public key."""
    return ECPoint.from_hex_encoded(text)


def sm2_get_public_key(private_key: int) -> ECPoint:
    """Compute the public key for a private key integer in [1, n-2]."""
    if not _is_private_scalar(private_key):
        raise ValueError("private key out of range")
    return ECPoint.generator().multiply(private_key)
