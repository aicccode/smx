#!/usr/bin/env python3
"""Seeded malformed-input harness for every public function, plus round-trip checks.

Usage: ``python tests/fuzz_public_api.py [--cases N] [--jobs N] [--seed N]``.

Each case asserts only the failure convention: a function either returns the type it
promises or raises ValueError, or TypeError when an argument has the wrong Python type.
``sm2_verify`` and ``sm2_check_sa`` must always return a bool, and the key exchange
functions may only raise ValueError, for a bad key length. Anything else, or a single
case running for more than ``CASE_LIMIT_SECONDS``, is a failure.
"""

from __future__ import annotations

import argparse
import array
import multiprocessing
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import smx
from smx import (
    SM2_N,
    SM2_P,
    SM3,
    SM4,
    ECPoint,
    hexutil,
    sm2_check_sa,
    sm2_decode_point,
    sm2_decrypt,
    sm2_encrypt,
    sm2_gen_key_pair,
    sm2_get_public_key,
    sm2_get_sa,
    sm2_get_sb,
    sm2_sign,
    sm2_verify,
    sm4,
    sm9_decapsulate,
    sm9_decrypt,
    sm9_decrypt_text,
    sm9_enc_master_public_key,
    sm9_encapsulate,
    sm9_encrypt,
    sm9_exchange_check,
    sm9_exchange_confirm,
    sm9_exchange_init,
    sm9_exchange_respond,
    sm9_gen_enc_user_key,
    sm9_gen_sign_user_key,
    sm9_sign,
    sm9_sign_master_public_key,
    sm9_verify,
)
from smx.sm2 import user_sm3_z

CASE_LIMIT_SECONDS = 5.0
PRIVATE = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
D = int(PRIVATE, 16)
PUBLIC_POINT = sm2_get_public_key(D)
PUBLIC = PUBLIC_POINT.to_hex_encoded()
G = ECPoint.generator()
R_POINT = sm2_get_public_key(12345)
OTHER_POINT = sm2_get_public_key(67890)
SIGNATURE = sm2_sign("id", "message", PRIVATE)
CIPHERTEXT = sm2_encrypt("message", PUBLIC)
SB = bytes.fromhex(
    sm2_get_sb(16, PUBLIC_POINT, R_POINT, OTHER_POINT, 7, R_POINT, 9, "a", "b").sb
)
EXCHANGE = sm2_get_sb(16, PUBLIC_POINT, R_POINT, OTHER_POINT, 7, R_POINT, 9, "a", "b")
CIPHER = SM4()
CIPHER.set_key(bytes(range(16)), bytes(16))
SM4_TEXT = CIPHER.encrypt("some valid text")
SM9_SIGN_MASTER = "1f2e3d4c5b6a79880102030405060708090a0b0c0d0e0f101112131415161718"
SM9_ENC_MASTER = "2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70819"
SM9_SIGN_PUBLIC = sm9_sign_master_public_key(SM9_SIGN_MASTER)
SM9_ENC_PUBLIC = sm9_enc_master_public_key(SM9_ENC_MASTER)
SM9_SIGN_KEY = sm9_gen_sign_user_key(SM9_SIGN_MASTER, "Alice")
SM9_ENC_KEY = sm9_gen_enc_user_key(SM9_ENC_MASTER, "Bob")
SM9_KEY_A = sm9_gen_enc_user_key(SM9_ENC_MASTER, "Alice", 2)
SM9_KEY_B = sm9_gen_enc_user_key(SM9_ENC_MASTER, "Bob", 2)
SM9_SIGNATURE = sm9_sign(b"message", SM9_SIGN_KEY, SM9_SIGN_PUBLIC)
SM9_CIPHERTEXT = sm9_encrypt(b"message", "Bob", SM9_ENC_PUBLIC)
SM9_KEM = sm9_encapsulate("Bob", SM9_ENC_PUBLIC, 16)[1]
SM9_RA_SECRET, SM9_RA = sm9_exchange_init("Bob", SM9_ENC_PUBLIC)
SM9_RB_SECRET, SM9_RB = sm9_exchange_init("Alice", SM9_ENC_PUBLIC)
SM9_SIDE_B = sm9_exchange_respond(
    16, "Alice", "Bob", SM9_ENC_PUBLIC, SM9_KEY_B, SM9_RB_SECRET, SM9_RB, SM9_RA
)
SM9_MODES = ("stream", "sm4", "STREAM", "", None, 1)

WEIRD_TEXT = (
    "",
    "0",
    "00",
    "0x",
    "0x00",
    " 00",
    "00\n",
    "h",
    "hh",
    "é" * 65,
    "٣" * 64,
    "\ud800",
    "\x00" * 64,
    "z" * 130,
    "f" * 64,
    "f" * 66,
    "0" * 64,
    "0" * 130,
    "04" + "0" * 128,
    "04" + "f" * 128,
)
_RELEASED_VIEW = memoryview(bytes(32))
_RELEASED_VIEW.release()
WRONG_TYPES = (
    _RELEASED_VIEW,
    ECPoint.__new__(ECPoint),
    None,
    0,
    1,
    -1,
    True,
    1.5,
    b"",
    b"00",
    bytearray(b"\x04"),
    memoryview(b"abc"),
    [],
    [1, 2],
    (),
    {},
    set(),
    object(),
    array.array("I", [1, 2, 3, 4]),
    2**64,
    -(2**64),
    2**300,
    float("nan"),
    float("inf"),
    int,
    print,
)
EDGE_INTS = (
    0,
    1,
    2,
    -1,
    SM2_N - 2,
    SM2_N - 1,
    SM2_N,
    SM2_N + 1,
    SM2_P,
    2**256,
    2**512,
    -(2**300),
)


class TypeMismatch(Exception):
    """A function returned something other than what it promises."""


def mutate_text(rng: random.Random, text: str) -> str:
    choice = rng.randrange(7)
    if not text:
        return rng.choice(WEIRD_TEXT)
    position = rng.randrange(len(text))
    if choice == 0:  # flip one hex digit
        return (
            text[:position]
            + rng.choice("0123456789abcdefABCDEF")
            + text[position + 1 :]
        )
    if choice == 1:  # remove
        return text[:position] + text[position + 1 :]
    if choice == 2:  # insert
        return text[:position] + rng.choice("0fzh é\n\ud800٣") + text[position:]
    if choice == 3:  # truncate
        return text[:position]
    if choice == 4:  # extend
        return text + "".join(
            rng.choice("0123456789abcdefh") for _ in range(rng.randrange(1, 9))
        )
    if choice == 5:  # swap the parts
        return text[position:] + text[:position]
    return text.upper() if rng.random() < 0.5 else "0x" + text


def any_text(rng: random.Random, valid: str = "") -> object:
    roll = rng.random()
    if roll < 0.55 and valid:
        return mutate_text(rng, valid)
    if roll < 0.75:
        return rng.choice(WEIRD_TEXT)
    if roll < 0.90:
        size = rng.randrange(0, 300)
        return "".join(rng.choice("0123456789abcdef") for _ in range(size))
    if roll < 0.95:
        size = rng.randrange(0, 40)
        return "".join(chr(rng.randrange(0x110000)) for _ in range(size))
    return rng.choice(WRONG_TYPES)


def any_bytes(rng: random.Random, valid: bytes = b"") -> object:
    roll = rng.random()
    if roll < 0.4 and valid:
        data = bytearray(valid)
        position = rng.randrange(len(data))
        data[position] ^= 1 << rng.randrange(8)
        return bytes(data)
    if roll < 0.55 and valid:
        return valid[: rng.randrange(len(valid))]
    if roll < 0.8:
        return bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 80)))
    if roll < 0.9:
        return bytes(rng.choice((15, 16, 17, 32, 64, 65, 66)))
    return rng.choice(WRONG_TYPES)


def any_int(rng: random.Random) -> object:
    roll = rng.random()
    if roll < 0.45:
        return rng.choice(EDGE_INTS)
    if roll < 0.7:
        return rng.getrandbits(rng.randrange(1, 600)) - rng.getrandbits(8)
    if roll < 0.8:
        return rng.randrange(1, SM2_N)
    return rng.choice(WRONG_TYPES)


def raw_point(rng: random.Random) -> ECPoint:
    """A point object that may be invalid in ways the constructor allows."""
    roll = rng.random()
    if roll < 0.35:
        return rng.choice((PUBLIC_POINT, R_POINT, OTHER_POINT, G))
    if roll < 0.45:
        return ECPoint.at_infinity()
    if roll < 0.75:
        return ECPoint(rng.randrange(SM2_P), rng.randrange(SM2_P))
    # Bypass the constructor, as unpickling would.
    point = object.__new__(ECPoint)
    for name, value in (
        ("x", any_int(rng)),
        ("y", any_int(rng)),
        ("infinity", rng.choice((False, True, None, 1, "x"))),
    ):
        object.__setattr__(point, name, value)
    return point


def any_point(rng: random.Random) -> object:
    return raw_point(rng) if rng.random() < 0.9 else rng.choice(WRONG_TYPES)


def is_type(value, kind) -> None:
    if not isinstance(value, kind):
        raise TypeMismatch(f"returned {type(value).__name__}, expected {kind}")


def f_hex_to_bytes(rng):
    is_type(hexutil.hex_to_bytes(any_text(rng, PUBLIC)), bytes)


def f_hex_to_int(rng):
    is_type(hexutil.hex_to_int(any_text(rng, PRIVATE)), int)


def f_bytes_to_hex(rng):
    is_type(hexutil.bytes_to_hex(any_bytes(rng)), str)


def f_bytes_to_hex_upper(rng):
    is_type(hexutil.bytes_to_hex_upper(any_bytes(rng)), str)


def f_lowercase_hex_to_bytes(rng):
    is_type(hexutil.lowercase_hex_to_bytes(any_text(rng, PUBLIC)), bytes)


def f_lowercase_hex_to_int(rng):
    is_type(hexutil.lowercase_hex_to_int(any_text(rng, PRIVATE)), int)


def f_sm3_update(rng):
    hasher = SM3()
    for _ in range(rng.randrange(1, 4)):
        is_type(hasher.update(any_bytes(rng)), SM3)
    if len(hasher.finish().hash_bytes()) != 32:
        raise AssertionError("digest size")


def f_sm3_update_byte(rng):
    is_type(SM3().update_byte(any_int(rng)), SM3)


def f_sm3_finish(rng):
    hasher = SM3()
    if rng.random() < 0.5:
        hasher.update(bytes(rng.randrange(200)))
    for _ in range(rng.randrange(4)):
        action = rng.choice((hasher.finish, hasher.hash_bytes, hasher.hash_hex_upper))
        action()
    if len(hasher.update(b"x").finish().hash_hex_upper()) != 64:
        raise AssertionError("digest size")


def f_pkcs7_pad(rng):
    is_type(sm4.pkcs7_pad(any_bytes(rng)), bytes)


def f_pkcs7_unpad(rng):
    is_type(sm4.pkcs7_unpad(any_bytes(rng, bytes(15) + b"\x01")), bytes)


def f_sm4_set_key(rng):
    SM4().set_key(any_bytes(rng, bytes(16)), any_bytes(rng, bytes(16)))


def f_sm4_encrypt_block(rng):
    is_type(CIPHER.encrypt_block(any_bytes(rng, bytes(16))), bytes)


def f_sm4_decrypt_block(rng):
    is_type(CIPHER.decrypt_block(any_bytes(rng, bytes(16))), bytes)


def f_sm4_encrypt(rng):
    is_type(CIPHER.encrypt(any_text(rng, "short text")), str)


def f_sm4_decrypt(rng):
    is_type(CIPHER.decrypt(any_text(rng, SM4_TEXT)), str)


def f_sm4_decrypt_bytes(rng):
    is_type(CIPHER.decrypt_bytes(any_text(rng, SM4_TEXT)), bytes)


def f_sm4_no_key(rng):
    fresh = SM4()
    call = rng.choice(
        (
            fresh.encrypt,
            fresh.decrypt,
            fresh.decrypt_bytes,
            fresh.encrypt_block,
            fresh.decrypt_block,
        )
    )
    call(any_text(rng, SM4_TEXT))


def f_point_constructor(rng):
    is_type(
        ECPoint(any_int(rng), any_int(rng), rng.choice((False, True, None, 1))), ECPoint
    )


def f_point_from_encoded(rng):
    is_type(ECPoint.from_encoded(any_bytes(rng, PUBLIC_POINT.to_encoded())), ECPoint)


def f_point_from_hex(rng):
    is_type(ECPoint.from_hex_encoded(any_text(rng, PUBLIC)), ECPoint)


def f_sm2_decode_point(rng):
    is_type(sm2_decode_point(any_text(rng, PUBLIC)), ECPoint)


def f_point_encoders(rng):
    point = raw_point(rng)
    is_type(rng.choice((point.to_encoded, point.x_bytes, point.y_bytes))(), bytes)


def f_point_to_hex(rng):
    is_type(raw_point(rng).to_hex_encoded(), str)


def f_point_is_on_curve(rng):
    is_type(raw_point(rng).is_on_curve(), bool)


def f_point_negate(rng):
    is_type(raw_point(rng).negate(), ECPoint)


def f_point_add(rng):
    is_type(raw_point(rng).add(any_point(rng)), ECPoint)


def f_point_subtract(rng):
    is_type(raw_point(rng).subtract(any_point(rng)), ECPoint)


def f_point_twice(rng):
    is_type(raw_point(rng).twice(), ECPoint)


def f_point_multiply(rng):
    is_type(raw_point(rng).multiply(any_int(rng)), ECPoint)


def f_sm2_get_public_key(rng):
    is_type(sm2_get_public_key(any_int(rng)), ECPoint)


def f_sm2_gen_key_pair(rng):
    private, public = sm2_gen_key_pair()
    if len(private) != 64 or len(public) != 130:
        raise AssertionError("key size")


def f_sm2_encrypt(rng):
    is_type(sm2_encrypt(any_text(rng, "short"), any_text(rng, PUBLIC)), str)


def f_sm2_decrypt(rng):
    is_type(sm2_decrypt(any_text(rng, CIPHERTEXT), any_text(rng, PRIVATE)), str)


def f_sm2_sign(rng):
    is_type(
        sm2_sign(any_text(rng, "id"), any_text(rng, "m"), any_text(rng, PRIVATE)), str
    )


def f_sm2_verify(rng):
    result = sm2_verify(
        any_text(rng, "id"),
        any_text(rng, SIGNATURE),
        any_text(rng, "message"),
        any_text(rng, PUBLIC),
    )
    is_type(result, bool)


def f_user_sm3_z(rng):
    is_type(user_sm3_z(any_bytes(rng, b"id"), any_point(rng)), bytes)


def f_sm2_get_sb(rng):
    keep = rng.random() < 0.1
    result = sm2_get_sb(
        16 if rng.random() < 0.7 else any_int(rng),
        PUBLIC_POINT if keep else any_point(rng),
        R_POINT if keep else any_point(rng),
        OTHER_POINT if keep else any_point(rng),
        any_int(rng),
        R_POINT if keep else any_point(rng),
        any_int(rng),
        any_text(rng, "a"),
        any_text(rng, "b"),
    )
    is_type(result, smx.SM2KeySwapParams)


def f_sm2_get_sa(rng):
    keep = rng.random() < 0.1
    result = sm2_get_sa(
        16 if rng.random() < 0.7 else any_int(rng),
        PUBLIC_POINT if keep else any_point(rng),
        R_POINT if keep else any_point(rng),
        OTHER_POINT if keep else any_point(rng),
        any_int(rng),
        R_POINT if keep else any_point(rng),
        any_int(rng),
        any_text(rng, "a"),
        any_text(rng, "b"),
        any_bytes(rng, SB),
    )
    is_type(result, smx.SM2KeySwapParams)


def f_sm2_check_sa(rng):
    result = sm2_check_sa(
        any_point(rng),
        any_bytes(rng, EXCHANGE.za),
        any_bytes(rng, EXCHANGE.zb),
        any_point(rng),
        any_point(rng),
        any_bytes(rng, SB),
    )
    is_type(result, bool)


def sm9_data(rng: random.Random, valid: str = "message") -> object:
    roll = rng.random()
    if roll < 0.4:
        return valid
    if roll < 0.6:
        return valid.encode()
    if roll < 0.8:
        return any_bytes(rng, valid.encode())
    return any_text(rng, valid)


def sm9_hid(rng: random.Random, valid: int) -> object:
    return valid if rng.random() < 0.7 else any_int(rng)


def sm9_mode(rng: random.Random) -> object:
    return rng.choice(SM9_MODES[:2]) if rng.random() < 0.8 else rng.choice(SM9_MODES)


def f_sm9_master_public_key(rng):
    function = rng.choice((sm9_sign_master_public_key, sm9_enc_master_public_key))
    is_type(function(any_text(rng, SM9_SIGN_MASTER)), str)


def f_sm9_gen_user_key(rng):
    function = rng.choice((sm9_gen_sign_user_key, sm9_gen_enc_user_key))
    result = function(
        any_text(rng, SM9_ENC_MASTER), sm9_data(rng, "Bob"), sm9_hid(rng, 3)
    )
    is_type(result, str)


def f_sm9_sign(rng):
    result = sm9_sign(
        sm9_data(rng),
        any_text(rng, SM9_SIGN_KEY),
        SM9_SIGN_PUBLIC if rng.random() < 0.5 else any_text(rng, SM9_SIGN_PUBLIC),
    )
    is_type(result, str)


def f_sm9_verify(rng):
    result = sm9_verify(
        sm9_data(rng),
        any_text(rng, SM9_SIGNATURE),
        sm9_data(rng, "Alice"),
        SM9_SIGN_PUBLIC if rng.random() < 0.5 else any_text(rng, SM9_SIGN_PUBLIC),
        sm9_hid(rng, 1),
    )
    is_type(result, bool)


def f_sm9_encrypt(rng):
    result = sm9_encrypt(
        sm9_data(rng),
        sm9_data(rng, "Bob"),
        SM9_ENC_PUBLIC if rng.random() < 0.5 else any_text(rng, SM9_ENC_PUBLIC),
        sm9_hid(rng, 3),
        sm9_mode(rng),
    )
    is_type(result, str)


def f_sm9_decrypt(rng):
    function = rng.choice((sm9_decrypt, sm9_decrypt_text))
    result = function(
        any_text(rng, SM9_CIPHERTEXT),
        sm9_data(rng, "Bob"),
        SM9_ENC_KEY if rng.random() < 0.5 else any_text(rng, SM9_ENC_KEY),
        sm9_mode(rng),
    )
    is_type(result, bytes if function is sm9_decrypt else str)


def f_sm9_encapsulate(rng):
    key_len = 16 if rng.random() < 0.7 else any_int(rng)
    result = sm9_encapsulate(
        sm9_data(rng, "Bob"),
        SM9_ENC_PUBLIC if rng.random() < 0.5 else any_text(rng, SM9_ENC_PUBLIC),
        key_len,
        sm9_hid(rng, 3),
    )
    is_type(result, tuple)


def f_sm9_decapsulate(rng):
    key_len = 16 if rng.random() < 0.7 else any_int(rng)
    result = sm9_decapsulate(
        any_text(rng, SM9_KEM),
        sm9_data(rng, "Bob"),
        SM9_ENC_KEY if rng.random() < 0.5 else any_text(rng, SM9_ENC_KEY),
        key_len,
    )
    is_type(result, str)


def f_sm9_exchange_init(rng):
    result = sm9_exchange_init(
        sm9_data(rng, "Bob"),
        SM9_ENC_PUBLIC if rng.random() < 0.5 else any_text(rng, SM9_ENC_PUBLIC),
        sm9_hid(rng, 2),
    )
    is_type(result, tuple)


def f_sm9_exchange_respond(rng):
    keep = rng.random() < 0.3
    result = sm9_exchange_respond(
        16 if rng.random() < 0.7 else any_int(rng),
        sm9_data(rng, "Alice"),
        sm9_data(rng, "Bob"),
        SM9_ENC_PUBLIC if keep else any_text(rng, SM9_ENC_PUBLIC),
        SM9_KEY_B if keep else any_text(rng, SM9_KEY_B),
        any_text(rng, SM9_RB_SECRET),
        any_text(rng, SM9_RB),
        any_text(rng, SM9_RA),
    )
    is_type(result, smx.SM9ExchangeResult)


def f_sm9_exchange_confirm(rng):
    keep = rng.random() < 0.3
    result = sm9_exchange_confirm(
        16 if rng.random() < 0.7 else any_int(rng),
        sm9_data(rng, "Alice"),
        sm9_data(rng, "Bob"),
        SM9_ENC_PUBLIC if keep else any_text(rng, SM9_ENC_PUBLIC),
        SM9_KEY_A if keep else any_text(rng, SM9_KEY_A),
        any_text(rng, SM9_RA_SECRET),
        any_text(rng, SM9_RA),
        any_text(rng, SM9_RB),
        any_text(rng, SM9_SIDE_B.s_b),
    )
    is_type(result, smx.SM9ExchangeResult)


def f_sm9_exchange_check(rng):
    result = sm9_exchange_check(
        any_text(rng, SM9_SIDE_B.s_2), any_text(rng, SM9_SIDE_B.s_2)
    )
    is_type(result, bool)


def f_set_key_cache_enabled(rng):
    smx.set_key_cache_enabled(rng.choice((True, False, None, 0, "x", 1.0)))
    smx.set_key_cache_enabled(True)


# Functions that may never raise, and those that may only raise ValueError.
NEVER_RAISE = {f_sm2_verify, f_sm2_check_sa, f_sm9_verify, f_sm9_exchange_check}
ONLY_VALUE_ERROR = {
    f_sm2_get_sb,
    f_sm2_get_sa,
    f_sm9_exchange_respond,
    f_sm9_exchange_confirm,
}
ALL_FUNCTIONS = tuple(
    value for name, value in sorted(globals().items()) if name.startswith("f_")
)
# This function takes no input, so there is nothing malformed to feed it.
KEY_PAIR_CASES = 2000
# SM9 cases that get through validation cost a pairing or a scalar multiplication.
SM9_CASES = 3000


def run_function(arguments):
    """Run one function's cases; return (name, cases, failures, seconds)."""
    name, cases, seed = arguments
    function = globals()[name]
    allowed: tuple = (ValueError, TypeError)
    if function in ONLY_VALUE_ERROR:
        allowed = (ValueError,)
    if function in NEVER_RAISE:
        allowed = ()
    if function is f_sm2_gen_key_pair:
        cases = min(cases, KEY_PAIR_CASES)
    if name.startswith("f_sm9_"):
        cases = min(cases, SM9_CASES)
    rng = random.Random(f"{seed}/{name}")
    failures = []
    outcomes = {"returned": 0, "rejected": 0}
    started = time.perf_counter()
    slowest = 0.0
    for case in range(cases):
        before = time.perf_counter()
        try:
            function(rng)
            outcomes["returned"] += 1
        except allowed:
            outcomes["rejected"] += 1
        except BaseException as error:  # noqa: BLE001 - this is what the harness looks for
            if len(failures) < 5:
                failures.append((case, type(error).__name__, str(error)[:200]))
        elapsed = time.perf_counter() - before
        slowest = max(slowest, elapsed)
        if elapsed > CASE_LIMIT_SECONDS and len(failures) < 5:
            failures.append((case, "slow", f"{elapsed:.1f}s"))
    seconds = time.perf_counter() - started
    return name, cases, outcomes, failures, seconds, slowest


# SM9 round trips cost tens of milliseconds, so only every few rounds runs one.
SM9_ROUND_TRIP_EVERY = 10


def sm9_round_trip(rng: random.Random, text: str, user: str, size: int) -> None:
    sign_key = sm9_gen_sign_user_key(SM9_SIGN_MASTER, user)
    signature = sm9_sign(text, sign_key, SM9_SIGN_PUBLIC)
    if not sm9_verify(text, signature, user, SM9_SIGN_PUBLIC):
        raise AssertionError("SM9 signature round trip")
    if sm9_verify(text + "x", signature, user, SM9_SIGN_PUBLIC):
        raise AssertionError("SM9 signature accepted another message")
    enc_key = sm9_gen_enc_user_key(SM9_ENC_MASTER, user)
    mode = rng.choice(("stream", "sm4"))
    ciphertext = sm9_encrypt(text, user, SM9_ENC_PUBLIC, mode=mode)
    if sm9_decrypt_text(ciphertext, user, enc_key, mode) != text:
        raise AssertionError("SM9 encryption round trip")
    key, kem = sm9_encapsulate(user, SM9_ENC_PUBLIC, size)
    if sm9_decapsulate(kem, user, enc_key, size) != key:
        raise AssertionError("SM9 KEM round trip")
    key_a = sm9_gen_enc_user_key(SM9_ENC_MASTER, user, 2)
    r_a, big_r_a = sm9_exchange_init("b", SM9_ENC_PUBLIC)
    r_b, big_r_b = sm9_exchange_init(user, SM9_ENC_PUBLIC)
    key_b = sm9_gen_enc_user_key(SM9_ENC_MASTER, "b", 2)
    side_b = sm9_exchange_respond(
        size, user, "b", SM9_ENC_PUBLIC, key_b, r_b, big_r_b, big_r_a
    )
    side_a = sm9_exchange_confirm(
        size, user, "b", SM9_ENC_PUBLIC, key_a, r_a, big_r_a, big_r_b, side_b.s_b
    )
    if not (
        side_a.success and side_b.success and side_a.shared_key == side_b.shared_key
    ):
        raise AssertionError("SM9 key exchange")
    if not sm9_exchange_check(side_b.s_2, side_a.s_a):
        raise AssertionError("SM9 key exchange confirmation")


def run_round_trips(arguments):
    """Check valid-input properties with random keys and messages."""
    rounds, seed = arguments
    rng = random.Random(f"{seed}/round-trip")
    alphabet = "abc 012é密€😀"
    started = time.perf_counter()
    for done in range(rounds):
        private, public = sm2_gen_key_pair()
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 200)))
        user = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 40)))
        if sm2_decrypt(sm2_encrypt(text, public), private) != text:
            raise AssertionError("SM2 encryption round trip")
        signature = sm2_sign(user, text, private)
        if not sm2_verify(user, signature, text, public):
            raise AssertionError("SM2 signature round trip")
        if sm2_verify(user, signature, text + "x", public):
            raise AssertionError("SM2 signature accepted another message")

        key = bytes(rng.getrandbits(8) for _ in range(16))
        iv = bytes(rng.getrandbits(8) for _ in range(16))
        cipher = SM4()
        cipher.set_key(key, iv)
        if cipher.decrypt(cipher.encrypt(text)) != text:
            raise AssertionError("SM4 round trip")
        block = bytes(rng.getrandbits(8) for _ in range(16))
        if cipher.decrypt_block(cipher.encrypt_block(block)) != block:
            raise AssertionError("SM4 block round trip")

        d_a, d_b, r_a, r_b = (rng.randrange(1, SM2_N - 1) for _ in range(4))
        p_a, p_b = sm2_get_public_key(d_a), sm2_get_public_key(d_b)
        big_ra, big_rb = sm2_get_public_key(r_a), sm2_get_public_key(r_b)
        size = rng.randrange(1, 100)
        side_b = sm2_get_sb(size, p_a, big_ra, p_b, d_b, big_rb, r_b, user, "b")
        side_a = sm2_get_sa(
            size,
            p_b,
            big_rb,
            p_a,
            d_a,
            big_ra,
            r_a,
            user,
            "b",
            bytes.fromhex(side_b.sb),
        )
        if not (side_a.success and side_b.success and side_a.ka == side_b.kb):
            raise AssertionError("key exchange")
        if not sm2_check_sa(
            side_b.v, side_b.za, side_b.zb, big_ra, big_rb, bytes.fromhex(side_a.sa)
        ):
            raise AssertionError("key exchange confirmation")
        if done % SM9_ROUND_TRIP_EVERY == 0:
            sm9_round_trip(rng, text, user, size)
    return rounds, time.perf_counter() - started


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=int, default=200_000)
    parser.add_argument("--round-trips", type=int, default=2000)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--seed", type=int, default=20261105)
    parser.add_argument("--only", default="", help="substring of the function name")
    args = parser.parse_args()

    names = [f.__name__ for f in ALL_FUNCTIONS if args.only in f.__name__]
    started = time.perf_counter()
    bad = 0
    with multiprocessing.Pool(args.jobs) as pool:
        work = [(name, args.cases, args.seed) for name in names]
        for name, cases, outcomes, failures, seconds, slowest in pool.imap_unordered(
            run_function, work
        ):
            print(
                f"{name[2:]:24s} {cases:8d} cases {outcomes['returned']:8d} returned "
                f"{outcomes['rejected']:8d} rejected {seconds:8.1f}s "
                f"slowest {slowest * 1e3:7.1f}ms",
                flush=True,
            )
            for failure in failures:
                bad += 1
                print(f"  FAILURE {name}: {failure}", flush=True)
        if not args.only and args.round_trips:
            shares = [
                (args.round_trips // args.jobs + 1, args.seed + i)
                for i in range(args.jobs)
            ]
            total = sum(
                rounds for rounds, _ in pool.imap_unordered(run_round_trips, shares)
            )
            print(f"round trips: {total} passed", flush=True)
    print(f"total {time.perf_counter() - started:.1f}s, {bad} failures")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
