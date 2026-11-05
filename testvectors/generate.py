#!/usr/bin/env python3
"""Generate shared security test vectors for every SMX language implementation.

The vectors are computed with plain Python integers, hashlib and the OpenSSL
command line. Nothing here imports the SMX library, so they are an independent
check of it. Usage: python3 generate.py > security-vectors.json
"""

from __future__ import annotations

import hashlib
import json
import subprocess

P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = P - 3
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
G = (GX, GY)

# Fixed test values. They are public and must never be used as real keys.
D = 0x3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8
K = 0x59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21
USER_ID = b"1234567812345678"
MESSAGE = b"message digest"
PLAINTEXT = b"encryption standard"
SM4_KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")
SM4_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def sm3(data: bytes) -> bytes:
    return hashlib.new("sm3", data).digest()


def add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        m = (3 * p[0] * p[0] + A) * pow(2 * p[1], -1, P) % P
    else:
        m = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (m * m - p[0] - q[0]) % P
    return x, (m * (p[0] - x) - p[1]) % P


def mul(k, p):
    r = None
    while k:
        if k & 1:
            r = add(r, p)
        p = add(p, p)
        k >>= 1
    return r


def b32(x: int) -> bytes:
    return x.to_bytes(32, "big")


def enc_point(p) -> bytes:
    return b"\x04" + b32(p[0]) + b32(p[1])


def z_value(user_id: bytes, pub) -> bytes:
    entl = (len(user_id) * 8).to_bytes(2, "big")
    return sm3(entl + user_id + b32(A) + b32(B) + b32(GX) + b32(GY) + b32(pub[0]) + b32(pub[1]))


def kdf(z: bytes, length: int) -> bytes:
    out = b""
    counter = 1
    while len(out) < length:
        out += sm3(z + counter.to_bytes(4, "big"))
        counter += 1
    return out[:length]


def sm4_cbc_nopad(data: bytes) -> bytes:
    """Encrypt raw blocks, so a test can decrypt to any chosen padding bytes."""
    return subprocess.run(
        ["openssl", "enc", "-sm4-cbc", "-e", "-nopad", "-K", SM4_KEY.hex(), "-iv", SM4_IV.hex()],
        input=data,
        capture_output=True,
        check=True,
    ).stdout


def sm3_of_zeros(size: int) -> str:
    h = hashlib.new("sm3")
    chunk = bytes(1 << 20)
    for _ in range(size >> 20):
        h.update(chunk)
    return h.hexdigest()


def named(pairs):
    return [{"name": n, "value": v} for n, v in pairs]


def main() -> None:
    pub = mul(D, G)
    assert (pub[1] ** 2 - pub[0] ** 3 - A * pub[0] - B) % P == 0

    z = z_value(USER_ID, pub)
    e = int.from_bytes(sm3(z + MESSAGE), "big")
    r = (e + mul(K, G)[0]) % N
    s = pow(1 + D, -1, N) * (K - r * D) % N
    hex_r, hex_s = b32(r).hex(), b32(s).hex()

    c1 = mul(K, G)
    shared = mul(K, pub)
    mask = kdf(b32(shared[0]) + b32(shared[1]), len(PLAINTEXT))
    c2 = bytes(a ^ b for a, b in zip(PLAINTEXT, mask))
    c3 = sm3(b32(shared[0]) + PLAINTEXT + b32(shared[1]))
    good_c1, good = enc_point(c1), enc_point(c1) + c3 + c2

    x_off = pub[0]
    off_curve = b"\x04" + b32(x_off) + b32((pub[1] + 1) % P)
    invalid_public_keys = named(
        [
            ("empty", ""),
            ("odd_length_hex", enc_point(pub).hex()[:-1]),
            ("non_hex", "zz" + enc_point(pub).hex()[2:]),
            ("non_ascii", "é" * 130),
            ("prefix_only", "04"),
            ("infinity_single_zero", "00"),
            ("short_by_one_byte", enc_point(pub)[:-1].hex()),
            ("long_by_one_byte", (enc_point(pub) + b"\x00").hex()),
            ("oversized", (enc_point(pub) * 8).hex()),
            ("wrong_prefix_05", "05" + enc_point(pub).hex()[2:]),
            ("x_y_zero", (b"\x04" + bytes(64)).hex()),
            ("not_on_curve", off_curve.hex()),
            ("x_equals_p", (b"\x04" + b32(P) + b32(pub[1])).hex()),
            ("y_equals_p", (b"\x04" + b32(pub[0]) + b32(P)).hex()),
            ("x_above_p_congruent", (b"\x04" + b32(pub[0] + P) + b32(pub[1])).hex())
            if pub[0] + P < 2**256
            else ("x_all_ones", (b"\x04" + b"\xff" * 32 + b32(pub[1])).hex()),
            ("y_above_p_congruent", (b"\x04" + b32(pub[0]) + b32(pub[1] + P)).hex())
            if pub[1] + P < 2**256
            else ("y_all_ones", (b"\x04" + b32(pub[0]) + b"\xff" * 32).hex()),
            # Accepted on the curve equation y^2 = x^3 + ax + b' for another b: an invalid-curve point.
            ("invalid_curve_small_x", (b"\x04" + b32(1) + b32(1)).hex()),
        ]
    )

    invalid_private_keys = named(
        [
            ("empty", ""),
            ("zero", b32(0).hex()),
            ("n", b32(N).hex()),
            ("n_minus_1", b32(N - 1).hex()),
            ("n_plus_1", b32(N + 1).hex()),
            ("all_ones", (b"\xff" * 32).hex()),
            ("oversized", "ff" + b32(D).hex()),
            ("non_hex", "zz" + b32(D).hex()[2:]),
            ("odd_length", b32(D).hex()[:-1] + "gg"),
        ]
    )

    sigs = [
        ("r_zero", b32(0).hex(), hex_s),
        ("s_zero", hex_r, b32(0).hex()),
        ("both_zero", b32(0).hex(), b32(0).hex()),
        ("r_equals_n", b32(N).hex(), hex_s),
        ("s_equals_n", hex_r, b32(N).hex()),
        ("r_all_ones", "ff" * 32, hex_s),
        ("s_all_ones", hex_r, "ff" * 32),
        ("r_plus_s_equals_n", hex_r, b32((N - r) % N).hex()),
        ("r_oversized_ff_prefix", "ff" + hex_r, hex_s),
        ("s_oversized_ff_prefix", hex_r, "ff" + hex_s),
        ("r_truncated", hex_r[:-2], hex_s),
        ("s_truncated", hex_r, hex_s[:-2]),
        ("r_non_hex", "zz" + hex_r[2:], hex_s),
        ("s_non_hex", hex_r, "zz" + hex_s[2:]),
        ("r_non_ascii", "é" * 32, hex_s),
        ("empty", "", ""),
        ("flipped_r_bit", b32(r ^ 1).hex(), hex_s),
        ("flipped_s_bit", hex_r, b32(s ^ 1).hex()),
    ]
    if r + N < 2**256:
        sigs.append(("r_plus_n_malleated", b32(r + N).hex(), hex_s))
    if s + N < 2**256:
        sigs.append(("s_plus_n_malleated", hex_r, b32(s + N).hex()))

    flipped_c3 = good_c1 + bytes([c3[0] ^ 1]) + c3[1:] + c2
    flipped_c2 = good_c1 + c3 + bytes([c2[0] ^ 1]) + c2[1:]
    invalid_ciphertexts = named(
        [
            ("empty", ""),
            ("odd_length_hex", good.hex()[:-1]),
            ("non_hex", "zz" + good.hex()[2:]),
            ("only_prefix", "04"),
            ("c1_only", good_c1.hex()),
            ("c1_and_c3_no_c2", (good_c1 + c3).hex()),
            ("truncated_c3", (good_c1 + c3[:10]).hex()),
            ("wrong_c1_prefix", ("05" + good.hex()[2:])),
            ("c1_not_on_curve", (off_curve + c3 + c2).hex()),
            ("c1_zero", (b"\x04" + bytes(64) + c3 + c2).hex()),
            ("c1_x_equals_p", (b"\x04" + b32(P) + b32(c1[1]) + c3 + c2).hex()),
            ("flipped_c3", flipped_c3.hex()),
            ("flipped_c2", flipped_c2.hex()),
            ("trailing_garbage", (good + b"\x00").hex()),
        ]
    )

    def padded(last_block: bytes) -> str:
        return sm4_cbc_nopad(last_block).hex()

    invalid_paddings = named(
        [
            ("zero_padding_byte", padded(b"A" * 15 + b"\x00")),
            ("padding_17", padded(b"A" * 15 + b"\x11")),
            ("padding_ff", padded(b"A" * 15 + b"\xff")),
            ("inconsistent_2", padded(b"A" * 14 + b"\x01\x02")),
            ("inconsistent_16", padded(b"\x10" * 15 + b"\x0f")),
        ]
    )
    good_sm4 = padded(b"hello world\x05\x05\x05\x05\x05")
    full_block = padded(b"\x10" * 16)

    vectors = {
        "_comment": "Public test values. Hex is lowercase. Ciphertext layout is C1 || C3 || C2.",
        "sm2": {
            "private_key": b32(D).hex(),
            "public_key": enc_point(pub).hex(),
            "user_id": USER_ID.decode(),
            "message": MESSAGE.decode(),
            "nonce_k": b32(K).hex(),
            "r": hex_r,
            "s": hex_s,
            "plaintext": PLAINTEXT.decode(),
            "ciphertext": good.hex(),
            "n_minus_2_is_max_valid_private_key": b32(N - 2).hex(),
            "invalid_public_keys": invalid_public_keys,
            "invalid_private_keys": invalid_private_keys,
            "invalid_signatures": [{"name": n, "r": a, "s": b} for n, a, b in sigs],
            "invalid_ciphertexts": invalid_ciphertexts,
            "user_id_max_bytes": 8191,
            "user_id_first_invalid_bytes": 8192,
        },
        "sm3": {
            "zeros_512_mib": sm3_of_zeros(512 << 20),
            "zeros_1024_mib": sm3_of_zeros(1024 << 20),
        },
        "sm4": {
            "key": SM4_KEY.hex(),
            "iv": SM4_IV.hex(),
            "valid_padded_ciphertext": good_sm4,
            "valid_padded_plaintext": "hello world",
            "valid_full_padding_block_ciphertext": full_block,
            "invalid_key_lengths_bytes": [0, 1, 15, 17, 24, 32],
            "invalid_iv_lengths_bytes": [0, 1, 15, 17, 32],
            "invalid_paddings": invalid_paddings,
            "invalid_ciphertext_lengths_bytes": [0, 1, 15, 17, 31],
        },
    }
    print(json.dumps(vectors, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
