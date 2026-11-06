#!/usr/bin/env python3
"""Summarize Mac kit results: median of per-run medians, plus spread across runs."""
import glob
import os
import re
import statistics
import sys

R = sys.argv[1]
OPS = [
    "sm3/64B", "sm3/1KB", "sm3/1MB",
    "sm4/key_schedule",
    "sm4/cbc_encrypt/16B", "sm4/cbc_encrypt/1KB", "sm4/cbc_encrypt/1MB",
    "sm4/cbc_decrypt/16B", "sm4/cbc_decrypt/1KB", "sm4/cbc_decrypt/1MB",
    "sm2/keygen", "sm2/sign", "sm2/verify", "sm2/encrypt/32B", "sm2/decrypt/32B", "sm2/key_exchange",
]
data = {}  # impl -> op -> [run medians]
for f in sorted(glob.glob(os.path.join(R, "*.txt"))):
    m = re.match(r"(.+)-(\d+)\.txt$", os.path.basename(f))
    if not m or m.group(1) == "system":
        continue
    impl = m.group(1)
    with open(f) as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2 and parts[0] in OPS and parts[1] != "NA":
                data.setdefault(impl, {}).setdefault(parts[0], []).append(float(parts[1]))

def value(impl, op):
    runs = data.get(impl, {}).get(op)
    return statistics.median(runs) if runs else None

def spread(impl, op):
    runs = data.get(impl, {}).get(op)
    if not runs or len(runs) < 2:
        return None
    return (max(runs) - min(runs)) / statistics.median(runs) * 100

impls = sorted(data)
print("op".ljust(22) + "".join(i[:14].rjust(15) for i in impls))
for op in OPS:
    row = op.ljust(22)
    for i in impls:
        v = value(i, op)
        row += (f"{v:15.3f}" if v is not None else "NA".rjust(15))
    print(row)
print("\nmax spread across runs (% of median), per impl:")
for i in impls:
    sp = [(spread(i, op), op) for op in OPS if spread(i, op) is not None]
    if sp:
        worst = max(sp)
        print(f"  {i:22} runs={len(next(iter(data[i].values())))} worst {worst[0]:.1f}% ({worst[1]}), median {statistics.median(s for s, _ in sp):.1f}%")
