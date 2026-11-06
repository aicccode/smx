#!/usr/bin/env python3
"""Markdown tables from Mac kit results. Throughput in MB/s (10^6 bytes) for SM3/SM4 data ops, microseconds otherwise.

Usage: table.py RESULTS_DIR             full before/after tables per algorithm
       table.py RESULTS_DIR --summary   compact tables used in the top-level README
"""
import glob
import os
import re
import statistics
import sys

R = sys.argv[1]
data = {}
for f in glob.glob(os.path.join(R, "*.txt")):
    m = re.match(r"(.+)-(\d+)\.txt$", os.path.basename(f))
    if not m:
        continue
    with open(f) as fh:
        for line in fh:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 2 and p[1] != "NA" and "/" in p[0]:
                data.setdefault(m.group(1), {}).setdefault(p[0], []).append(float(p[1]))

def us(impl, op):
    v = data.get(impl, {}).get(op)
    return statistics.median(v) if v else None

SIZE = {"64B": 64, "16B": 16, "1KB": 1024, "1MB": 1048576}
def fmt(op, t):
    if t is None:
        return "—"
    size = SIZE.get(op.rsplit("/", 1)[-1])
    if op.startswith(("sm3/", "sm4/cbc")) and size:
        mbs = size / t
        return f"{mbs:.0f}" if mbs >= 100 else (f"{mbs:.1f}" if mbs >= 1 else f"{mbs:.3f}")
    return f"{t:.0f}" if t >= 100 else (f"{t:.1f}" if t >= 10 else f"{t:.2f}")

LANGS = [("c", "C"), ("rust", "Rust"), ("go", "Go"), ("csharp", "C#"), ("java", "Java"),
         ("javascript", "JavaScript"), ("python", "Python"), ("swift", "Swift")]
REFS = [(k, n) for k, n in [("openssl-3.0.13", "OpenSSL 3.0.13"), ("openssl-3.6.5", "OpenSSL 3.6.5"),
                            ("bc", "BouncyCastle 1.86")] if k in data]

def table(title, unit, ops):
    print(f"\n### {title}（{unit}）\n")
    print("| 实现 | " + " | ".join(h for _, h in ops) + " |")
    print("|---|" + "---|" * len(ops))
    for k, n in REFS:
        print(f"| {n} | " + " | ".join(fmt(o, us(k, o)) for o, _ in ops) + " |")
    for k, n in LANGS:
        cells = []
        for o, _ in ops:
            b, a = us(f"{k}-base", o), us(f"{k}-new", o)
            if b is None or a is None:
                cells.append("—")
                continue
            ratio = b / a
            mark = f"**{ratio:.2f}×**" if ratio >= 1 else f"{ratio:.2f}×"
            cells.append(f"{fmt(o, b)} → {fmt(o, a)}（{mark}）")
        print(f"| {n} | " + " | ".join(cells) + " |")

SUMMARY = [("sm3/1MB", "SM3 1 MiB（MB/s）"), ("sm4/cbc_encrypt/1MB", "SM4-CBC 加密 1 MiB（MB/s）"),
           ("sm4/cbc_decrypt/1MB", "SM4-CBC 解密 1 MiB（MB/s）"), ("sm2/keygen", "SM2 密钥生成（µs）"),
           ("sm2/sign", "SM2 签名（µs）"), ("sm2/verify", "SM2 验签（µs）"), ("sm2/encrypt/32B", "SM2 加密 32 B（µs）"),
           ("sm2/decrypt/32B", "SM2 解密 32 B（µs）"), ("sm2/key_exchange", "SM2 密钥交换（µs）")]

def summary():
    """Two compact tables: current numbers next to the references, and speed-up over the old code."""
    refs = [(k, n) for k, n in REFS if k != "openssl-3.0.13"]
    print("| 操作 | " + " | ".join(n for _, n in refs + LANGS) + " |")
    print("|---|" + "---|" * (len(refs) + len(LANGS)))
    for o, label in SUMMARY:
        cells = [fmt(o, us(k, o)) for k, _ in refs] + [fmt(o, us(f"{k}-new", o)) for k, _ in LANGS]
        print(f"| {label} | " + " | ".join(cells) + " |")
    print("\n| 操作 | " + " | ".join(n for _, n in LANGS) + " |")
    print("|---|" + "---|" * len(LANGS))
    for o, label in SUMMARY:
        cells = []
        for k, _ in LANGS:
            b, a = us(f"{k}-base", o), us(f"{k}-new", o)
            r = b / a
            cells.append(f"**{r:.1f}×**" if r >= 1 else f"{r:.2f}×")
        print(f"| {label.split('（')[0]} | " + " | ".join(cells) + " |")

if len(sys.argv) > 2 and sys.argv[2] == "--summary":
    summary()
    sys.exit()

table("SM3 哈希", "MB/s，越大越好", [("sm3/64B", "64 B"), ("sm3/1KB", "1 KiB"), ("sm3/1MB", "1 MiB")])
table("SM4-CBC 加密", "MB/s，越大越好", [("sm4/cbc_encrypt/16B", "16 B"), ("sm4/cbc_encrypt/1KB", "1 KiB"), ("sm4/cbc_encrypt/1MB", "1 MiB")])
table("SM4-CBC 解密", "MB/s，越大越好", [("sm4/cbc_decrypt/16B", "16 B"), ("sm4/cbc_decrypt/1KB", "1 KiB"), ("sm4/cbc_decrypt/1MB", "1 MiB")])
table("SM4 密钥扩展", "µs，越小越好", [("sm4/key_schedule", "设置密钥")])
table("SM2 密钥生成、签名、验签", "µs，越小越好", [("sm2/keygen", "密钥生成"), ("sm2/sign", "签名"), ("sm2/verify", "验签")])
table("SM2 加解密", "µs，越小越好", [("sm2/encrypt/32B", "加密 32 B"), ("sm2/decrypt/32B", "解密 32 B")])
table("SM2 密钥交换", "µs，越小越好，含双方计算和确认", [("sm2/key_exchange", "一次完整交换")])
