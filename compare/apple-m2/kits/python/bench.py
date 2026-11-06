"""SM2/SM3/SM4 benchmark for one side of the kit: python3 bench.py <side directory>.

Prints "<name>\t<median_us>\t<min_us>" for each operation. Python 3.9 stdlib only.
"""

import secrets
import statistics
import sys
import time

sys.path.insert(0, sys.argv[1])

from smx import (  # noqa: E402
    SM3,
    SM4,
    sm2_check_sa,
    sm2_decode_point,
    sm2_decrypt,
    sm2_encrypt,
    sm2_gen_key_pair,
    sm2_get_sa,
    sm2_get_sb,
    sm2_sign,
    sm2_verify,
)

USER_ID = "1234567812345678"
ID_B = "BILL456@YAHOO.COM"
SAMPLES = 7
MIN_SAMPLE_SECONDS = 0.2
WARMUP_SECONDS = 0.5
KIB = 1024
MIB = 1024 * KIB
clock = time.perf_counter
sink = []


def measure(name, operation):
    """Warm up, then take SAMPLES samples of at least MIN_SAMPLE_SECONDS each."""
    start = clock()
    calls = 0
    while True:
        sink.append(operation())
        calls += 1
        if clock() - start >= WARMUP_SECONDS:
            break
    per_call = (clock() - start) / calls
    batch = max(1, int(MIN_SAMPLE_SECONDS / per_call) + 1)
    results = []
    for _ in range(SAMPLES):
        start = clock()
        for _ in range(batch):
            sink.append(operation())
        results.append((clock() - start) / batch * 1e6)
        del sink[:]
    print(f"{name}\t{statistics.median(results):.3f}\t{min(results):.3f}", flush=True)


def check(condition, message):
    if not condition:
        raise SystemExit(f"self-check failed: {message}")


def self_check(private, public):
    check(
        SM3().update(b"abc").finish().hash_hex_upper()
        == "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0",
        "SM3 abc",
    )
    cipher = SM4()
    cipher.set_key(bytes.fromhex("0123456789abcdeffedcba9876543210"), bytes(16))
    check(
        cipher.encrypt_block(bytes.fromhex("0123456789abcdeffedcba9876543210")).hex()
        == "681edf34d206965e86b3e94f536e4246",
        "SM4 standard block",
    )
    message = "m" * 32
    signature = sm2_sign(USER_ID, message, private)
    check(sm2_verify(USER_ID, signature, message, public), "sign then verify")
    check(not sm2_verify(USER_ID, signature, message + "x", public), "verify rejects")
    plaintext = "p" * 32
    check(
        sm2_decrypt(sm2_encrypt(plaintext, public), private) == plaintext,
        "SM2 round trip",
    )


def key_exchange_setup():
    d_a, p_a = sm2_gen_key_pair()
    d_b, p_b = sm2_gen_key_pair()
    return int(d_a, 16), sm2_decode_point(p_a), int(d_b, 16), sm2_decode_point(p_b)


def make_key_exchange(d_a, p_a, d_b, p_b):
    def key_exchange():
        # Fresh ephemeral keys for both sides, as a real exchange needs.
        ra_hex, big_ra_hex = sm2_gen_key_pair()
        rb_hex, big_rb_hex = sm2_gen_key_pair()
        ra, big_ra = int(ra_hex, 16), sm2_decode_point(big_ra_hex)
        rb, big_rb = int(rb_hex, 16), sm2_decode_point(big_rb_hex)
        side_b = sm2_get_sb(16, p_a, big_ra, p_b, d_b, big_rb, rb, USER_ID, ID_B)
        side_a = sm2_get_sa(
            16,
            p_b,
            big_rb,
            p_a,
            d_a,
            big_ra,
            ra,
            USER_ID,
            ID_B,
            bytes.fromhex(side_b.sb),
        )
        confirmed = sm2_check_sa(
            side_b.v, side_b.za, side_b.zb, big_ra, big_rb, bytes.fromhex(side_a.sa)
        )
        if not (
            side_a.success and side_b.success and confirmed and side_a.ka == side_b.kb
        ):
            raise SystemExit("self-check failed: key exchange")
        return side_a.ka

    return key_exchange


def main():
    private, public = sm2_gen_key_pair()
    self_check(private, public)
    exchange = make_key_exchange(*key_exchange_setup())
    exchange()

    for name, size in (("64B", 64), ("1KB", KIB), ("1MB", MIB)):
        data = secrets.token_bytes(size)
        measure(
            f"sm3/{name}", lambda data=data: SM3().update(data).finish().hash_bytes()
        )

    key, iv = secrets.token_bytes(16), secrets.token_bytes(16)

    def key_schedule():
        cipher = SM4()
        cipher.set_key(key, iv)
        return cipher

    measure("sm4/key_schedule", key_schedule)
    cipher = SM4()
    cipher.set_key(key, iv)
    texts = {}
    for name, size in (("16B", 16), ("1KB", KIB), ("1MB", MIB)):
        text = "".join(secrets.choice("abcdefghijklmnop") for _ in range(size))
        texts[name] = (text, cipher.encrypt(text))
        check(cipher.decrypt(texts[name][1]) == text, f"SM4 round trip {name}")
    for name in ("16B", "1KB", "1MB"):
        measure(f"sm4/cbc_encrypt/{name}", lambda t=texts[name][0]: cipher.encrypt(t))
    for name in ("16B", "1KB", "1MB"):
        measure(f"sm4/cbc_decrypt/{name}", lambda c=texts[name][1]: cipher.decrypt(c))

    message = "m" * 32
    signature = sm2_sign(USER_ID, message, private)
    plaintext = "p" * 32
    ciphertext = sm2_encrypt(plaintext, public)
    measure("sm2/keygen", sm2_gen_key_pair)
    measure("sm2/sign", lambda: sm2_sign(USER_ID, message, private))
    measure("sm2/verify", lambda: sm2_verify(USER_ID, signature, message, public))
    measure("sm2/encrypt/32B", lambda: sm2_encrypt(plaintext, public))
    measure("sm2/decrypt/32B", lambda: sm2_decrypt(ciphertext, private))
    measure("sm2/key_exchange", exchange)
    check(
        all(sm2_verify(USER_ID, signature, message, public) for _ in range(2)), "final"
    )


if __name__ == "__main__":
    main()
