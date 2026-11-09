"""SM9 identity-based cryptography (GB/T 38635): signatures, encryption, KEM, key exchange.

Encodings (hex strings, lowercase on output):

- scalars (master private keys, the key exchange r): 32 bytes big endian
- G1 points (signing user keys, encryption master public keys, ciphertext C1, R_A,
  R_B): ``04 || x || y``, 65 bytes
- G2 points (signing master public keys, encryption user keys):
  ``04 || x1 || x0 || y1 || y0``, 129 bytes, x = x0 + x1*u
- signatures ``h || S`` (97 bytes); ciphertexts ``C1 || C3 || C2``; KEM ciphertexts C

Keys and points are accepted in either case and must decode to a valid value: scalars
in [1, n-1], points on the curve and, for G2, in the subgroup of order n. Signatures
and ciphertexts (including KEM ciphertexts) must be lowercase, so each value has a
single accepted spelling. Identities and messages are bytes, or str encoded as UTF-8.

Per-key caches: decoded master public keys and the pairings e(P1, Ppub-s) and
e(Ppub-e, P2), with their power tables, are kept per master public key (public values
only) while ``smx.set_key_cache_enabled`` is on, and dropped by
``smx.clear_key_caches``. User private keys are never cached.

Timing: CPython integers give no constant-time guarantee (see :mod:`smx._ec`). Secret
scalars and exponents use fixed windows with full-table masked lookups; MACs and
confirmation values are compared with ``hmac.compare_digest``. Decoding a user private
key checks it like any point (on the curve, and [n]Q = O for G2) with variable-time
formulas whose schedule depends only on public constants; pairings run a schedule fixed
by the curve parameter. The SM4 mode uses the table-based SM4 of :mod:`smx.sm4`, which
is not cache-timing resistant.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field

from . import _ec
from . import _sm9_curve as curve
from . import _sm9_field as gt
from ._sm9_common import (
    G1_HEX_LEN,
    MODE_SM4,
    MODE_STREAM,
    _base,
    _check_hid,
    _check_key_length,
    _check_mode,
    _data_bytes,
    _enc_master,
    _g1_hex,
    _g2_hex,
    _h1,
    _h2,
    _Master,
    _parse_g1,
    _parse_g2,
    _parse_scalar,
    _random_scalar,
    _scalar_hex,
    _sign_master,
    _user_point,
)
from ._sm9_pairing import pairing
from .hexutil import bytes_to_hex, lowercase_hex_to_bytes
from .sm2 import _MAX_KDF_BYTES, _kdf
from .sm3 import _digest
from .sm4 import (
    _crypt_bytes,
    _decrypt_blocks,
    _expand_key,
    _group_round_keys,
    _padding_is_bad,
    pkcs7_pad,
)

SM9_HID_SIGN = 0x01
SM9_HID_EXCHANGE = 0x02
SM9_HID_ENCRYPT = 0x03
SM9_MODE_STREAM = MODE_STREAM
SM9_MODE_SM4 = MODE_SM4
SM9_N = gt.N
SM9_Q = gt.Q

_N = gt.N
_G1 = curve.G1
_G2 = curve.G2
_HASH_SIZE = 32
_SIGNATURE_LEN = _HASH_SIZE + curve.G1_BYTES
_C1_SIZE = curve.G1_BYTES
_MAC_KEY_LEN = 32
_SM4_KEY_LEN = 16
_SM4_BLOCK = 16
_MAX_RETRIES = 128  # each retry has a negligible chance of being needed at all
_DECRYPT_ERROR = "decryption failed"
_DECAPSULATE_ERROR = "decapsulation failed"
_TAG_SB = b"\x82"
_TAG_SA = b"\x83"


@dataclass(frozen=True)
class SM9ExchangeResult:
    """Result of one side of the SM9 key exchange.

    ``s_b`` and ``s_2`` are set by the responder, ``s_a`` by the initiator.
    """

    success: bool = False
    message: str = ""
    # The shared key is secret, so repr() must not show it.
    shared_key: str = field(default="", repr=False)
    s_a: str = ""
    s_b: str = ""
    s_2: str = ""


# ---------------------------------------------------------------- key generation


def _user_scalar(master_private: int, identity: bytes, hid: int) -> int:
    t1 = (_h1(identity, hid) + master_private) % _N
    if t1 == 0:
        return 0
    return master_private * _ec.invert_blinded(t1, _N) % _N


def sm9_sign_master_public_key(master_private_key: str) -> str:
    """Ppub-s = [ks]P2 for a signing master private key (64 hex digits)."""
    ks = _parse_scalar(master_private_key, "master private key")
    point = _G2.to_affine(curve.mul_secret(_G2, curve.P2, ks, _base("p2_secret")))
    return _g2_hex(point)


def sm9_enc_master_public_key(master_private_key: str) -> str:
    """Ppub-e = [ke]P1 for an encryption master private key (64 hex digits)."""
    ke = _parse_scalar(master_private_key, "master private key")
    point = _G1.to_affine(curve.mul_secret(_G1, curve.P1, ke, _base("p1_secret")))
    return _g1_hex(point)


def sm9_gen_sign_master_key() -> tuple[str, str]:
    """Return ``(master_private_hex, master_public_hex)`` with Ppub-s in G2."""
    private = _scalar_hex(_random_scalar())
    return private, sm9_sign_master_public_key(private)


def sm9_gen_enc_master_key() -> tuple[str, str]:
    """Return ``(master_private_hex, master_public_hex)`` with Ppub-e in G1."""
    private = _scalar_hex(_random_scalar())
    return private, sm9_enc_master_public_key(private)


def sm9_gen_sign_user_key(
    master_private_key: str, user_id, hid: int = SM9_HID_SIGN
) -> str:
    """ds = [ks / (H1(ID || hid) + ks)]P1, a G1 point."""
    ks = _parse_scalar(master_private_key, "master private key")
    del master_private_key
    identity = _data_bytes(user_id, "user id")
    t2 = _user_scalar(ks, identity, _check_hid(hid))
    del ks
    if t2 == 0:
        raise ValueError("this identity cannot have a key under this master key")
    point = _G1.to_affine(curve.mul_secret(_G1, curve.P1, t2, _base("p1_secret")))
    return _g1_hex(point)


def sm9_gen_enc_user_key(
    master_private_key: str, user_id, hid: int = SM9_HID_ENCRYPT
) -> str:
    """de = [ke / (H1(ID || hid) + ke)]P2, a G2 point; also used for key exchange."""
    ke = _parse_scalar(master_private_key, "master private key")
    del master_private_key
    identity = _data_bytes(user_id, "user id")
    t2 = _user_scalar(ke, identity, _check_hid(hid))
    del ke
    if t2 == 0:
        raise ValueError("this identity cannot have a key under this master key")
    point = _G2.to_affine(curve.mul_secret(_G2, curve.P2, t2, _base("p2_secret")))
    return _g2_hex(point)


# ---------------------------------------------------------------- signatures


def _sign_with_r(message: bytes, ds: tuple, master: _Master, r: int) -> str | None:
    w = gt.pow_secret(master.g_table, r)
    h = _h2(message, gt.to_bytes(w))
    l_value = (r - h) % _N
    if l_value == 0:
        return None
    s = _G1.to_affine(curve.mul_secret(_G1, ds, l_value))
    return bytes_to_hex(h.to_bytes(_HASH_SIZE, "big") + curve.g1_to_bytes(s))


def _sign_known_r(
    message, user_private_key: str, master_public_key: str, r: int
) -> str:
    """Signing with a given r, for known-answer tests only. Never use a chosen r."""
    data = _data_bytes(message, "message")
    ds = _parse_g1(user_private_key, "user private key")
    signature = _sign_with_r(data, ds, _sign_master(master_public_key), r)
    if signature is None:
        raise ValueError("signing failed")
    return signature


def sm9_sign(message, user_private_key: str, master_public_key: str) -> str:
    """Sign and return ``h || S`` as lowercase hex (194 digits)."""
    data = _data_bytes(message, "message")
    master = _sign_master(master_public_key)
    ds = _parse_g1(user_private_key, "user private key")
    del user_private_key
    for _ in range(_MAX_RETRIES):
        signature = _sign_with_r(data, ds, master, _random_scalar())
        if signature is not None:
            return signature
    raise ValueError("signing failed")


def _verify(
    message, signature, user_id, master_public_key, hid
) -> bool:  # any failure raises
    data = _data_bytes(message, "message")
    identity = _data_bytes(user_id, "user id")
    hid = _check_hid(hid)
    if not isinstance(signature, str) or len(signature) != 2 * _SIGNATURE_LEN:
        return False
    raw = lowercase_hex_to_bytes(signature)
    h = int.from_bytes(raw[:_HASH_SIZE], "big")
    if not 1 <= h <= _N - 1:
        return False
    s = curve.g1_from_bytes(raw[_HASH_SIZE:])
    if s is None:
        return False
    master = _sign_master(master_public_key)
    t = gt.pow_public(master.g, h)
    p = _G2.to_affine(
        curve.g2_add_affine(
            _base("p2_public").multiply(_h1(identity, hid)), master.point
        ),
        False,
    )
    u = pairing(s, p)
    return _h2(data, gt.to_bytes(gt.mul(u, t))) == h


def sm9_verify(
    message, signature: str, user_id, master_public_key: str, hid: int = SM9_HID_SIGN
) -> bool:
    """Verify ``h || S``. Any malformed input of any kind returns False."""
    try:
        return _verify(message, signature, user_id, master_public_key, hid)
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------- KEM and encryption


def _key_material(c1: tuple, w: tuple, identity: bytes, length: int) -> bytes:
    return _kdf(length, (curve.g1_xy(c1), gt.to_bytes(w), identity))


def _encapsulate_with_r(
    identity: bytes, q_b: tuple, table: int, master: _Master, key_len: int, r: int
) -> tuple[str, str] | None:
    c = _G1.to_affine(curve.mul_secret(_G1, q_b, r, table))
    key = _key_material(c, gt.pow_secret(master.g_table, r), identity, key_len)
    if not any(key):
        return None
    return bytes_to_hex(key), _g1_hex(c)


def _encapsulate(user_id, master_public_key, key_len, hid, r_source) -> tuple[str, str]:
    identity = _data_bytes(user_id, "user id")
    key_len = _check_key_length(key_len)
    hid = _check_hid(hid)
    master = _enc_master(master_public_key)
    q_b = _user_point(identity, hid, master)
    table = curve.secret_table(_G1, q_b)
    for _ in range(_MAX_RETRIES):
        result = _encapsulate_with_r(identity, q_b, table, master, key_len, r_source())
        if result is not None:
            return result
    raise ValueError("encapsulation failed")


def _encapsulate_known_r(
    user_id, master_public_key, key_len, hid, r
) -> tuple[str, str]:
    """Encapsulation with a given r, for known-answer tests only."""
    return _encapsulate(user_id, master_public_key, key_len, hid, lambda: r)


def sm9_encapsulate(
    user_id, master_public_key: str, key_len: int, hid: int = SM9_HID_ENCRYPT
) -> tuple[str, str]:
    """Return ``(key_hex, ciphertext_hex)``, key_len bytes for the identity's key."""
    return _encapsulate(user_id, master_public_key, key_len, hid, _random_scalar)


def sm9_decapsulate(
    ciphertext: str, user_id, user_private_key: str, key_len: int
) -> str:
    """Recover the KEM key; every failure after argument checks raises one ValueError."""
    identity = _data_bytes(user_id, "user id")
    key_len = _check_key_length(key_len)
    de = _parse_g2(user_private_key, "user private key")
    del user_private_key
    key = _decapsulate(ciphertext, identity, de, key_len)
    del de
    if key is None:
        raise ValueError(_DECAPSULATE_ERROR)
    return key


def _decapsulate(ciphertext, identity: bytes, de: tuple, key_len: int) -> str | None:
    if not isinstance(ciphertext, str):
        raise TypeError("ciphertext must be a hex string")
    if len(ciphertext) != G1_HEX_LEN:
        return None
    try:
        c = curve.g1_from_bytes(lowercase_hex_to_bytes(ciphertext))
    except ValueError:
        return None
    if c is None:
        return None
    key = _key_material(c, pairing(c, de), identity, key_len)
    return bytes_to_hex(key) if any(key) else None


def _sm4_keys(key: bytes, decrypt: bool) -> tuple:
    expanded = _expand_key(key)
    return _group_round_keys(expanded[::-1] if decrypt else expanded)


def _encrypt_with_r(
    message: bytes,
    identity: bytes,
    q_b: tuple,
    table: int,
    master: _Master,
    block: bool,
    r: int,
) -> str | None:
    c1 = _G1.to_affine(curve.mul_secret(_G1, q_b, r, table))
    w = gt.pow_secret(master.g_table, r)
    k1_len = _SM4_KEY_LEN if block else len(message)
    key = _key_material(c1, w, identity, k1_len + _MAC_KEY_LEN)
    k1, k2 = key[:k1_len], key[k1_len:]
    if not any(k1):
        return None
    if block:
        c2 = _crypt_bytes(pkcs7_pad(message), _sm4_keys(k1, False), None)
    else:
        c2 = (int.from_bytes(message, "big") ^ int.from_bytes(k1, "big")).to_bytes(
            len(message), "big"
        )
    c3 = _digest(c2 + k2)
    return _g1_hex(c1) + bytes_to_hex(c3) + bytes_to_hex(c2)


def _encrypt(plaintext, user_id, master_public_key, hid, mode, r_source) -> str:
    message = _data_bytes(plaintext, "plaintext")
    identity = _data_bytes(user_id, "user id")
    hid = _check_hid(hid)
    block = _check_mode(mode)
    if not message:
        raise ValueError("plaintext cannot be empty")
    if len(message) > _MAX_KDF_BYTES - _MAC_KEY_LEN:
        raise ValueError("plaintext too long")
    master = _enc_master(master_public_key)
    q_b = _user_point(identity, hid, master)
    table = curve.secret_table(_G1, q_b)
    for _ in range(_MAX_RETRIES):
        result = _encrypt_with_r(
            message, identity, q_b, table, master, block, r_source()
        )
        if result is not None:
            return result
    raise ValueError("encryption failed")


def _encrypt_known_r(plaintext, user_id, master_public_key, hid, mode, r) -> str:
    """Encryption with a given r, for known-answer tests only."""
    return _encrypt(plaintext, user_id, master_public_key, hid, mode, lambda: r)


def sm9_encrypt(
    plaintext,
    user_id,
    master_public_key: str,
    hid: int = SM9_HID_ENCRYPT,
    mode: str = SM9_MODE_STREAM,
) -> str:
    """Encrypt to an identity; returns ``C1 || C3 || C2`` as lowercase hex."""
    return _encrypt(plaintext, user_id, master_public_key, hid, mode, _random_scalar)


def _decrypt_parts(ciphertext, identity: bytes, de: tuple, block: bool) -> bytes | None:
    if not isinstance(ciphertext, str):
        raise TypeError("ciphertext must be a hex string")
    minimum = 2 * (_C1_SIZE + _HASH_SIZE + 1)
    if len(ciphertext) < minimum or len(ciphertext) % 2:
        return None
    try:
        data = lowercase_hex_to_bytes(ciphertext)
    except ValueError:
        return None
    c1 = curve.g1_from_bytes(data[:_C1_SIZE])
    c3 = data[_C1_SIZE : _C1_SIZE + _HASH_SIZE]
    c2 = data[_C1_SIZE + _HASH_SIZE :]
    if c1 is None or len(c2) > _MAX_KDF_BYTES - _MAC_KEY_LEN:
        return None
    if block and len(c2) % _SM4_BLOCK:
        return None
    k1_len = _SM4_KEY_LEN if block else len(c2)
    key = _key_material(c1, pairing(c1, de), identity, k1_len + _MAC_KEY_LEN)
    k1, k2 = key[:k1_len], key[k1_len:]
    if not any(k1):
        return None
    # The MAC is checked before anything is decrypted or unpadded.
    if not hmac.compare_digest(_digest(c2 + k2), c3):
        return None
    if not block:
        value = int.from_bytes(c2, "big") ^ int.from_bytes(k1, "big")
        return value.to_bytes(len(c2), "big")
    plain = _decrypt_blocks(c2, _sm4_keys(k1, True))
    if _padding_is_bad(plain):
        return None
    return plain[: -plain[-1]]


def sm9_decrypt(
    ciphertext: str, user_id, user_private_key: str, mode: str = SM9_MODE_STREAM
) -> bytes:
    """Decrypt lowercase ``C1 || C3 || C2`` hex and return the plaintext bytes.

    Invalid arguments (user id, key, mode) raise their own errors; everything about
    the ciphertext, including a wrong mode, identity or key, raises one ValueError.
    """
    identity = _data_bytes(user_id, "user id")
    block = _check_mode(mode)
    de = _parse_g2(user_private_key, "user private key")
    del user_private_key
    plain = _decrypt_parts(ciphertext, identity, de, block)
    del de
    if plain is None:
        raise ValueError(_DECRYPT_ERROR)
    return plain


def _decode_utf8(data: bytes) -> str | None:
    """Decode without letting an exception, which quotes the data, leave this frame."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def sm9_decrypt_text(
    ciphertext: str, user_id, user_private_key: str, mode: str = SM9_MODE_STREAM
) -> str:
    """:func:`sm9_decrypt` for a UTF-8 plaintext; invalid UTF-8 gives the same error."""
    text = _decode_utf8(sm9_decrypt(ciphertext, user_id, user_private_key, mode))
    if text is None:
        raise ValueError(_DECRYPT_ERROR)
    return text


# ---------------------------------------------------------------- key exchange


def _exchange_init(peer_id, master_public_key, hid, r: int) -> tuple[str, str]:
    identity = _data_bytes(peer_id, "peer id")
    hid = _check_hid(hid)
    master = _enc_master(master_public_key)
    q_peer = _user_point(identity, hid, master)
    big_r = _G1.to_affine(curve.mul_secret(_G1, q_peer, r))
    return _scalar_hex(r), _g1_hex(big_r)


def sm9_exchange_init(
    peer_id, master_public_key: str, hid: int = SM9_HID_EXCHANGE
) -> tuple[str, str]:
    """Return ``(r_hex, R_hex)``, R = [r]Q_peer. Keep r secret and use it once."""
    return _exchange_init(peer_id, master_public_key, hid, _random_scalar())


def _exchange_inputs(id_a, id_b, master_public_key, user_private_key, r_hex, own, peer):
    """Parse everything; returns the values, or an error message string."""
    try:
        ids = _data_bytes(id_a, "user id"), _data_bytes(id_b, "user id")
    except (TypeError, ValueError):
        return "invalid user id"
    try:
        master = _enc_master(master_public_key)
    except (TypeError, ValueError):
        return "invalid master public key"
    try:
        de = _parse_g2(user_private_key, "user private key")
    except (TypeError, ValueError):
        return "invalid user private key"
    try:
        r = _parse_scalar(r_hex, "r")
    except (TypeError, ValueError):
        return "r out of range"
    points = []
    for text, name in ((own, "own"), (peer, "peer")):
        try:
            points.append(_parse_g1(text, name))
        except (TypeError, ValueError):
            return f"{name} R point is not valid"
    return ids, master, de, r, points[0], points[1]


def _exchange_hashes(ids, r_a, r_b, g1, g2, g3, key_len) -> tuple[bytes, bytes, bytes]:
    """Return (shared key, inner hash, g1 bytes)."""
    tail = (ids[0], ids[1], curve.g1_xy(r_a), curve.g1_xy(r_b))
    g_bytes = gt.to_bytes(g1), gt.to_bytes(g2), gt.to_bytes(g3)
    key = _kdf(key_len, (*tail, *g_bytes))
    inner = _digest(b"".join((g_bytes[1], g_bytes[2], *tail)))
    return key, inner, g_bytes[0]


def sm9_exchange_respond(
    key_len: int,
    id_a,
    id_b,
    master_public_key: str,
    user_private_key_b: str,
    r_b: str,
    big_r_b: str,
    big_r_a: str,
) -> SM9ExchangeResult:
    """Responder B: shared key, S_B to send, and S_2 to compare with A's S_A.

    A key length outside 1 to 1 MiB raises ValueError; every other invalid input gives
    ``success=False``.
    """
    key_len = _check_key_length(key_len)
    parsed = _exchange_inputs(
        id_a, id_b, master_public_key, user_private_key_b, r_b, big_r_b, big_r_a
    )
    del user_private_key_b, r_b
    if isinstance(parsed, str):
        return SM9ExchangeResult(message=parsed)
    ids, master, de, r, own, peer = parsed
    g1 = pairing(peer, de)
    g2 = gt.pow_secret(master.g_table, r)
    g3 = gt.pow_secret(gt.odd_powers_table(g1), r)
    del de, r
    key, inner, g1_bytes = _exchange_hashes(ids, peer, own, g1, g2, g3, key_len)
    return SM9ExchangeResult(
        success=True,
        shared_key=bytes_to_hex(key),
        s_b=bytes_to_hex(_digest(_TAG_SB + g1_bytes + inner)),
        s_2=bytes_to_hex(_digest(_TAG_SA + g1_bytes + inner)),
    )


def _confirmation_bytes(text) -> bytes | None:
    if not isinstance(text, str) or len(text) != 2 * _HASH_SIZE:
        return None
    try:
        return lowercase_hex_to_bytes(text)  # one string form, like signatures
    except ValueError:
        return None


def sm9_exchange_confirm(
    key_len: int,
    id_a,
    id_b,
    master_public_key: str,
    user_private_key_a: str,
    r_a: str,
    big_r_a: str,
    big_r_b: str,
    s_b: str,
) -> SM9ExchangeResult:
    """Initiator A: check B's S_B, then return the shared key and S_A.

    A key length outside 1 to 1 MiB raises ValueError; every other invalid input,
    including an S_B that does not match, gives ``success=False``.
    """
    key_len = _check_key_length(key_len)
    parsed = _exchange_inputs(
        id_a, id_b, master_public_key, user_private_key_a, r_a, big_r_a, big_r_b
    )
    del user_private_key_a, r_a
    if isinstance(parsed, str):
        return SM9ExchangeResult(message=parsed)
    expected = _confirmation_bytes(s_b)
    if expected is None:
        return SM9ExchangeResult(message="B's verification value does not match")
    ids, master, de, r, own, peer = parsed
    g1 = gt.pow_secret(master.g_table, r)
    g2 = pairing(peer, de)
    g3 = gt.pow_secret(gt.odd_powers_table(g2), r)
    del de, r
    key, inner, g1_bytes = _exchange_hashes(ids, own, peer, g1, g2, g3, key_len)
    if not hmac.compare_digest(_digest(_TAG_SB + g1_bytes + inner), expected):
        return SM9ExchangeResult(message="B's verification value does not match")
    return SM9ExchangeResult(
        success=True,
        shared_key=bytes_to_hex(key),
        s_a=bytes_to_hex(_digest(_TAG_SA + g1_bytes + inner)),
    )


def sm9_exchange_check(s_2: str, s_a: str) -> bool:
    """B's last step: compare S_2 with A's S_A in constant time. Bad input is False."""
    expected = _confirmation_bytes(s_2)
    received = _confirmation_bytes(s_a)
    if expected is None or received is None:
        return False
    return hmac.compare_digest(expected, received)
