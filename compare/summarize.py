#!/usr/bin/env python3
"""Summarize compare/run-all.sh output: python3 summarize.py [results-dir]. Times are microseconds per operation, best of all runs."""

import glob
import os
import re
import sys

O = sys.argv[1] if len(sys.argv) > 1 else "out"
U = {"ns": 1e-3, "us": 1, "µs": 1, "ms": 1e3}
rx = re.compile(r"^(.*?)\s+([\d.]+)\s*(ns|us|µs|ms)/op")
canon = [
    ("sm3 64", r"sm3[ /]64b|^BenchmarkSM3/64B"),
    ("sm3 1k", r"sm3[ /](1kb|1024b)|^BenchmarkSM3/1KB"),
    ("sm3 1m", r"sm3[ /](1mb|1048576b)|^BenchmarkSM3/1MB"),
    ("sm4 ks", r"sm4[ /_]key.?schedule|BenchmarkSM4KeySchedule"),
    ("sm4 enc 16", r"sm4(-cbc)?[ /_](enc|encrypt)[ _]16b|SM4Encrypt/16B"),
    ("sm4 dec 16", r"sm4(-cbc)?[ /_](dec|decrypt)[ _]16b|SM4Decrypt/16B"),
    ("sm4 enc 1k", r"sm4(-cbc)?[ /_](enc|encrypt)[ _](1kb|1024b)|SM4Encrypt/1KB"),
    ("sm4 dec 1k", r"sm4(-cbc)?[ /_](dec|decrypt)[ _](1kb|1024b)|SM4Decrypt/1KB"),
    ("sm4 enc 1m", r"sm4(-cbc)?[ /_](enc|encrypt)[ _](1mb|1048576b)|SM4Encrypt/1MB"),
    ("sm4 dec 1m", r"sm4(-cbc)?[ /_](dec|decrypt)[ _](1mb|1048576b)|SM4Decrypt/1MB"),
    ("sm2 keygen", r"sm2[ /]keygen$|SM2KeyGen"),
    ("sm2 sign", r"sm2[ /]sign$|SM2Sign"),
    ("sm2 verify", r"sm2[ /]verify$|SM2Verify"),
    ("sm2 enc", r"sm2[ /]encrypt( 19b| 32b|_32b)?$|SM2Encrypt/32B"),
    ("sm2 dec", r"sm2[ /]decrypt( 19b| 32b|_32b)?$|SM2Decrypt/32B"),
]
d = {}
langs = []
for f in sorted(glob.glob(O + "/*-[0-9].txt")):
    m = re.match(r"(\w+)-\d", os.path.basename(f))
    if not m:
        continue
    lang = m.group(1)
    if lang not in langs:
        langs.append(lang)
    with open(f, errors="replace") as fh:
        lines = fh.read().splitlines()
    for l in lines:
        if lang == "go":
            g = re.match(r"^(Benchmark\S+?)(?:-\d+)?\s+\d+\s+([\d.]+) ns/op", l)
            if not g:
                continue
            k, v = g.group(1), float(g.group(2)) * 1e-3
        elif lang == "js":
            g = re.match(r"^(.*?)\s+[\d.]+ ops/s\s+([\d.]+) us/op", l)
            if not g:
                continue
            k, v = g.group(1).strip(), float(g.group(2))
        else:
            g = rx.match(l)
            if not g:
                continue
            k, v = g.group(1).strip(), float(g.group(2)) * U[g.group(3)]
        for c, p in canon:
            if re.search(p, k, re.IGNORECASE):
                if "(cold)" in k:
                    continue
                d.setdefault(c, {})
                d[c][lang] = min(v, d[c].get(lang, 1e30))
                break
order = [
    x
    for x in [
        "openssl",
        "bc",
        "c",
        "rust",
        "go",
        "csharp",
        "java",
        "js",
        "python",
        "swift",
    ]
    if x in langs
]
print(f"{'op':11}" + "".join(f"{l:>11}" for l in order))
for c, _ in canon:
    r = d.get(c, {})
    print(
        f"{c:11}" + "".join(f"{r[l]:11.2f}" if l in r else f"{'-':>11}" for l in order)
    )
print("\nratio to openssl (>1 = faster than openssl)")
for c, _ in canon:
    r = d.get(c, {})
    o = r.get("openssl")
    if o:
        print(
            f"{c:11}"
            + "".join(f"{o / r[l]:11.2f}" if l in r else f"{'-':>11}" for l in order)
        )
print("\nratio to bc")
for c, _ in canon:
    r = d.get(c, {})
    o = r.get("bc")
    if o:
        print(
            f"{c:11}"
            + "".join(f"{o / r[l]:11.2f}" if l in r else f"{'-':>11}" for l in order)
        )
