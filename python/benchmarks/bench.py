#!/usr/bin/env python3
"""Throughput and latency benchmark for the smx package (standard library only).

Usage::

    python benchmarks/bench.py [--root DIR] [--min-time SECONDS] [--repeat N]

``--root`` selects the directory that contains the ``smx`` package, which lets
the same script measure another checkout. Each case reports the best of
``--repeat`` timed runs of at least ``--min-time`` seconds. Cases named
``(cold)`` clear the library's internal caches before every operation, when the
library has them, so they show the cost of a first use with a new key.
"""

from __future__ import annotations

import argparse
import gc
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from time import perf_counter
from typing import Callable

ID_A = "ALICE123@YAHOO.COM"
ID_B = "BILL456@YAHOO.COM"
D_A = int("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE", 16)
RA = int("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563", 16)
D_B = int("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53", 16)
RB = int("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80", 16)
PRIVATE = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
MESSAGE = "encryption standard"
KIB = 1024
MIB = 1024 * KIB


def measure(func: Callable[[], object], min_time: float, repeat: int) -> float:
    """Return the best observed seconds per call."""
    best = float("inf")
    for _ in range(repeat):
        count = 0
        gc.collect()
        start = perf_counter()
        while True:
            func()
            count += 1
            elapsed = perf_counter() - start
            if elapsed >= min_time:
                break
        best = min(best, elapsed / count)
    return best


def sm3_cases(smx) -> Iterator[tuple[str, Callable[[], object], int]]:
    for name, size in (("64B", 64), ("1KB", KIB), ("1MB", MIB)):
        data = bytes(range(256)) * (size // 256) + bytes(size % 256)

        def run(payload: bytes = data) -> bytes:
            return smx.SM3().update(payload).finish().hash_bytes()

        yield f"sm3 {name}", run, size


def sm4_cases(smx) -> Iterator[tuple[str, Callable[[], object], int]]:
    cipher = smx.SM4()
    cipher.set_key(b"0123456789abcdef", b"fedcba9876543210")
    block = bytes(range(16))
    yield "sm4 raw block encrypt", lambda: cipher.encrypt_block(block), 16
    yield "sm4 raw block decrypt", lambda: cipher.decrypt_block(block), 16

    def key_schedule() -> None:
        smx.SM4().set_key(b"0123456789abcdef", b"fedcba9876543210")

    yield "sm4 key schedule", key_schedule, 0

    # 16B/1KB/1MB are ciphertext payload sizes: the plaintext is one byte shorter,
    # so PKCS#7 adds a single byte and the ciphertext has exactly this size.
    for name, size in (("16B", 16), ("1KB", KIB), ("1MB", MIB)):
        plaintext = "x" * (size - 16 + 15)
        ciphertext = cipher.encrypt(plaintext)

        def encrypt(text: str = plaintext) -> str:
            return cipher.encrypt(text)

        def decrypt(text: str = ciphertext) -> str:
            return cipher.decrypt(text)

        yield f"sm4-cbc encrypt {name}", encrypt, size
        yield f"sm4-cbc decrypt {name}", decrypt, size


def sm2_cases(smx, clear_caches) -> Iterator[tuple[str, Callable[[], object], int]]:
    public = smx.sm2_get_public_key(int(PRIVATE, 16)).to_hex_encoded()
    signature = smx.sm2_sign(ID_A, MESSAGE, PRIVATE)
    ciphertext = smx.sm2_encrypt(MESSAGE, public)
    point = smx.ECPoint.from_hex_encoded(public)
    generator = smx.ECPoint.generator()
    scalar = int(PRIVATE, 16)
    keys = (
        smx.sm2_get_public_key(D_A),
        smx.sm2_get_public_key(RA),
        smx.sm2_get_public_key(D_B),
        smx.sm2_get_public_key(RB),
    )

    def exchange() -> None:
        p_a, r_a, p_b, r_b = keys
        side_b = smx.sm2_get_sb(16, p_a, r_a, p_b, D_B, r_b, RB, ID_A, ID_B)
        side_a = smx.sm2_get_sa(
            16, p_b, r_b, p_a, D_A, r_a, RA, ID_A, ID_B, bytes.fromhex(side_b.sb)
        )
        assert side_a.success and side_a.ka == side_b.kb

    def sign() -> str:
        return smx.sm2_sign(ID_A, MESSAGE, PRIVATE)

    def verify() -> None:
        assert smx.sm2_verify(ID_A, signature, MESSAGE, public)

    def cold(func: Callable[[], object]) -> Callable[[], object]:
        def run() -> object:
            clear_caches()
            return func()

        return run

    yield "ec G*k", lambda: generator.multiply(scalar), 0
    yield "ec P*k", lambda: point.multiply(scalar), 0
    yield "sm2 keygen", smx.sm2_gen_key_pair, 0
    yield "sm2 sign", sign, 0
    yield "sm2 sign (cold)", cold(sign), 0
    yield "sm2 verify", verify, 0
    yield "sm2 verify (cold)", cold(verify), 0
    yield "sm2 encrypt", lambda: smx.sm2_encrypt(MESSAGE, public), 0
    yield "sm2 encrypt (cold)", cold(lambda: smx.sm2_encrypt(MESSAGE, public)), 0
    yield "sm2 decrypt", lambda: smx.sm2_decrypt(ciphertext, PRIVATE), 0
    yield "sm2 key exchange (both sides)", exchange, 0
    yield "sm2 key exchange (cold)", cold(exchange), 0


def format_result(name: str, seconds: float, size: int) -> str:
    rate = f"{size / seconds / MIB:10.3f} MiB/s" if size else " " * 16
    return f"{name:32s} {seconds * 1e6:14.2f} us/op {1 / seconds:12.1f} op/s {rate}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    default_root = Path(__file__).resolve().parents[1]
    parser.add_argument("--root", type=Path, default=default_root)
    parser.add_argument("--min-time", type=float, default=0.3)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--filter", default="", help="substring of the case name")
    parser.add_argument("--json", type=Path, help="also write results to this file")
    args = parser.parse_args()

    sys.path.insert(0, str(args.root.resolve()))
    start = perf_counter()
    import smx

    print(f"python {sys.version.split()[0]}; smx from {Path(smx.__file__).parent}")
    print(f"import smx: {(perf_counter() - start) * 1e3:.2f} ms")
    clear_caches = getattr(smx.sm2, "_clear_caches", lambda: None)

    results: dict[str, float] = {}
    groups = (sm3_cases(smx), sm4_cases(smx), sm2_cases(smx, clear_caches))
    for group in groups:
        for name, func, size in group:
            if args.filter in name:
                results[name] = measure(func, args.min_time, args.repeat)
                print(format_result(name, results[name], size), flush=True)
    if args.json:
        args.json.write_text(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
