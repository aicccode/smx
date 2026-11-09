"""Shared SM9 helpers: argument parsing, H1/H2, fixed-base tables, master-key caches.

Private to :mod:`smx.sm9`; see there for the encodings and the cache policy.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from . import _ec
from . import _sm9_curve as curve
from . import _sm9_field as gt
from ._sm9_pairing import pairing
from .hexutil import as_bytes, bytes_to_hex, hex_to_bytes
from .sm2 import _kdf

_N = gt.N
_G1 = curve.G1
_G2 = curve.G2
_SCALAR_HEX_LEN = 64
G1_HEX_LEN = 2 * curve.G1_BYTES
G2_HEX_LEN = 2 * curve.G2_BYTES
_HASH_TO_RANGE_LEN = 40  # hlen = 8 * ceil(5 * 256 / 32) bits = 320 bits
_MAX_KEY_BYTES = 1 << 20
_MASTER_CACHE_SIZE = 32
MODE_STREAM = "stream"
MODE_SM4 = "sm4"


# ---------------------------------------------------------------- input handling


def _random_scalar() -> int:
    """Uniform in [1, n-1] from the OS CSPRNG (``secrets`` rejects, so no bias).

    A failing OS generator raises OSError; no other source is ever tried.
    """
    return secrets.randbelow(_N - 1) + 1


def _data_bytes(value, name: str) -> bytes:
    """bytes-like values as they are; str as UTF-8."""
    if isinstance(value, str):
        # The exception must not be raised inside the handler: UnicodeError keeps the
        # whole text and quotes part of it.
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError:
            encoded = None
        if encoded is None:
            raise ValueError(f"{name} is not valid text")
        return encoded
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:  # a released memoryview raises ValueError
            return as_bytes(value)
        except ValueError:
            pass
        raise ValueError(f"{name} is not readable")
    raise TypeError(f"{name} must be bytes or str")


def _check_hid(hid) -> int:
    if not isinstance(hid, int) or isinstance(hid, bool) or not 0 <= hid <= 0xFF:
        raise ValueError("hid must be an integer in [0, 255]")
    return hid


def _check_key_length(key_len) -> int:
    if (
        not isinstance(key_len, int)
        or isinstance(key_len, bool)
        or not 1 <= key_len <= _MAX_KEY_BYTES
    ):
        raise ValueError("key length must be between 1 and 1048576")
    return key_len


def _check_mode(mode) -> bool:
    """Return True for the SM4 mode, False for the stream mode."""
    if isinstance(mode, str) and mode in (MODE_STREAM, MODE_SM4):
        return mode == MODE_SM4
    raise ValueError("mode must be SM9_MODE_STREAM or SM9_MODE_SM4")


def _hex_of_length(text, length: int, name: str) -> bytes:
    if not isinstance(text, str):
        raise TypeError(f"{name} must be a hex string")
    if len(text) != length:
        raise ValueError(f"{name} must be {length} hex digits")
    try:
        return hex_to_bytes(text)
    except ValueError:
        pass
    raise ValueError(f"{name} is not valid hex")


def _parse_scalar(text, name: str) -> int:
    value = int.from_bytes(_hex_of_length(text, _SCALAR_HEX_LEN, name), "big")
    if not 1 <= value <= _N - 1:
        raise ValueError(f"{name} out of range")
    return value


def _parse_g1(text, name: str) -> tuple:
    point = curve.g1_from_bytes(_hex_of_length(text, G1_HEX_LEN, name))
    if point is None:
        raise ValueError(f"{name} is not a valid G1 point")
    return point


def _parse_g2(text, name: str) -> tuple:
    point = curve.g2_from_bytes(_hex_of_length(text, G2_HEX_LEN, name))
    if point is None:
        raise ValueError(f"{name} is not a valid G2 point")
    return point


def _scalar_hex(value: int) -> str:
    return bytes_to_hex(value.to_bytes(32, "big"))


def _g1_hex(point: tuple) -> str:
    return bytes_to_hex(curve.g1_to_bytes(point))


def _g2_hex(point: tuple) -> str:
    return bytes_to_hex(curve.g2_to_bytes(point))


# ---------------------------------------------------------------- hashes


def _hash_to_range(tag: int, *parts: bytes) -> int:
    """H1/H2: Ha = SM3(tag||Z||1) || SM3(tag||Z||2)[:8], then (Ha mod (n-1)) + 1."""
    ha = _kdf(_HASH_TO_RANGE_LEN, (bytes([tag]), *parts))
    return int.from_bytes(ha, "big") % (_N - 1) + 1


def _h1(identity: bytes, hid: int) -> int:
    return _hash_to_range(1, identity, bytes([hid]))


def _h2(*parts: bytes) -> int:
    return _hash_to_range(2, *parts)


# ---------------------------------------------------------------- fixed bases and caches

_bases: dict[str, object] = {}


def _base(name: str):
    """Tables for P1 and P2, built on first use (public, not per key)."""
    value = _bases.get(name)
    if value is None:
        if name == "p1_secret":
            value = curve.secret_table(_G1, curve.P1)
        elif name == "p2_secret":
            value = curve.secret_table(_G2, curve.P2)
        elif name == "p1_public":
            value = curve.FixedBase(_G1, curve.P1)
        else:
            value = curve.FixedBase(_G2, curve.P2)
        _bases[name] = value
    return value


@dataclass(frozen=True)
class _Master:
    """A decoded master public key with its pairing value and power table."""

    point: tuple
    g: tuple
    g_table: int


_sign_masters: dict[bytes, _Master] = {}
_enc_masters: dict[bytes, _Master] = {}


def _clear_caches() -> None:
    _sign_masters.clear()
    _enc_masters.clear()


_ec.cache_clearers.append(_clear_caches)


def _cached_master(cache: dict, key: bytes, build) -> _Master | None:
    if not _ec.key_cache_enabled:
        return build()
    master = cache.get(key)
    if master is None:
        master = build()
        if master is None:
            return None
        if len(cache) >= _MASTER_CACHE_SIZE:
            cache.clear()
        cache[key] = master
        if not _ec.key_cache_enabled:  # disabled by another thread during the call
            cache.clear()
    return master


def _sign_master(text) -> _Master:
    """Decode Ppub-s (G2) and compute g = e(P1, Ppub-s)."""
    data = _hex_of_length(text, G2_HEX_LEN, "master public key")

    def build() -> _Master | None:
        point = curve.g2_from_bytes(data)
        if point is None:
            return None
        g = pairing(curve.P1, point)
        return _Master(point, g, gt.odd_powers_table(g))

    master = _cached_master(_sign_masters, data, build)
    if master is None:
        raise ValueError("master public key is not a valid G2 point")
    return master


def _enc_master(text) -> _Master:
    """Decode Ppub-e (G1) and compute g = e(Ppub-e, P2)."""
    data = _hex_of_length(text, G1_HEX_LEN, "master public key")

    def build() -> _Master | None:
        point = curve.g1_from_bytes(data)
        if point is None:
            return None
        g = pairing(point, curve.P2)
        return _Master(point, g, gt.odd_powers_table(g))

    master = _cached_master(_enc_masters, data, build)
    if master is None:
        raise ValueError("master public key is not a valid G1 point")
    return master


def _user_point(identity: bytes, hid: int, master: _Master) -> tuple:
    """Q = [H1(ID || hid)]P1 + Ppub-e, public; the identity point is refused."""
    h = _h1(identity, hid)
    point = _G1.to_affine(
        curve.g1_add_affine(_base("p1_public").multiply(h), master.point), False
    )
    if point is None:
        raise ValueError("identity maps to the point at infinity")
    return point
