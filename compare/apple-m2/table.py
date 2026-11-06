#!/usr/bin/env python3
"""Markdown tables from Mac kit results. Throughput in MB/s (10^6 bytes) for SM3/SM4 data ops, microseconds otherwise.

Usage: table.py [--summary] [--lang zh|en|es] RESULTS_DIR [RESULTS_DIR ...]

Result files are named <impl>-<run>.txt. For each language, <lang>-base is the code before the rework (3397c6d),
<lang>-new the `security` branch (constant-time SM4) and <lang>-perf the `main` branch (table-based SM4).
Without --summary: full tables per algorithm. With --summary: the compact tables used in the top-level READMEs.
"""
import glob
import os
import re
import statistics
import sys

args = sys.argv[1:]
SUMMARY_MODE = "--summary" in args
LANG = "zh"
if "--lang" in args:
    LANG = args[args.index("--lang") + 1]
    args.remove("--lang")
    args.remove(LANG)
dirs = [a for a in args if a != "--summary"]

data = {}
for d in dirs:
    for f in glob.glob(os.path.join(d, "*.txt")):
        m = re.match(r"(.+)-(\d+)\.txt$", os.path.basename(f))
        if not m:
            continue
        with open(f) as fh:
            for line in fh:
                p = line.rstrip("\n").split("\t")
                if len(p) >= 2 and p[1] != "NA" and "/" in p[0]:
                    data.setdefault(m.group(1), {}).setdefault(p[0], []).append(float(p[1]))

T = {
    "zh": {
        "impl": "实现", "op": "操作", "base": "改造前", "new": "security", "perf": "main",
        "mbs": "MB/s，越大越好", "us": "µs，越小越好", "kx_unit": "µs，越小越好，含双方计算和确认",
        "sm3": "SM3 哈希", "enc": "SM4-CBC 加密", "dec": "SM4-CBC 解密", "ks": "SM4 密钥扩展", "setkey": "设置密钥",
        "sm2a": "SM2 密钥生成、签名、验签", "keygen": "密钥生成", "sign": "签名", "verify": "验签",
        "sm2b": "SM2 加解密", "e32": "加密 32 B", "d32": "解密 32 B", "kx": "SM2 密钥交换", "kx1": "一次完整交换",
        "s_sm3": "SM3 1 MiB（MB/s）", "s_enc": "SM4-CBC 加密 1 MiB（MB/s）", "s_dec": "SM4-CBC 解密 1 MiB（MB/s）",
        "s_ks": "SM4 密钥扩展（µs）", "s_keygen": "SM2 密钥生成（µs）", "s_sign": "SM2 签名（µs）",
        "s_verify": "SM2 验签（µs）", "s_e32": "SM2 加密 32 B（µs）", "s_d32": "SM2 解密 32 B（µs）",
        "s_kx": "SM2 密钥交换（µs）", "lang": "语言",
        "sm4_cols": ["加密 1 MiB（MB/s）", "解密 1 MiB（MB/s）", "密钥扩展（µs）"],
    },
    "en": {
        "impl": "Implementation", "op": "Operation", "base": "before", "new": "security", "perf": "main",
        "mbs": "MB/s, higher is better", "us": "µs, lower is better",
        "kx_unit": "µs, lower is better, both sides including confirmation",
        "sm3": "SM3 hash", "enc": "SM4-CBC encryption", "dec": "SM4-CBC decryption", "ks": "SM4 key schedule",
        "setkey": "Set key", "sm2a": "SM2 key generation, signing, verification", "keygen": "Key generation",
        "sign": "Sign", "verify": "Verify", "sm2b": "SM2 encryption and decryption", "e32": "Encrypt 32 B",
        "d32": "Decrypt 32 B", "kx": "SM2 key exchange", "kx1": "One full exchange",
        "s_sm3": "SM3 1 MiB (MB/s)", "s_enc": "SM4-CBC encrypt 1 MiB (MB/s)", "s_dec": "SM4-CBC decrypt 1 MiB (MB/s)",
        "s_ks": "SM4 key schedule (µs)", "s_keygen": "SM2 key generation (µs)", "s_sign": "SM2 sign (µs)",
        "s_verify": "SM2 verify (µs)", "s_e32": "SM2 encrypt 32 B (µs)", "s_d32": "SM2 decrypt 32 B (µs)",
        "s_kx": "SM2 key exchange (µs)", "lang": "Language",
        "sm4_cols": ["Encrypt 1 MiB (MB/s)", "Decrypt 1 MiB (MB/s)", "Key schedule (µs)"],
    },
    "es": {
        "impl": "Implementación", "op": "Operación", "base": "antes", "new": "security", "perf": "main",
        "mbs": "MB/s, más es mejor", "us": "µs, menos es mejor",
        "kx_unit": "µs, menos es mejor, ambas partes con confirmación",
        "sm3": "Hash SM3", "enc": "Cifrado SM4-CBC", "dec": "Descifrado SM4-CBC", "ks": "Expansión de clave SM4",
        "setkey": "Fijar clave", "sm2a": "SM2: generación de claves, firma y verificación",
        "keygen": "Generación de claves", "sign": "Firma", "verify": "Verificación",
        "sm2b": "Cifrado y descifrado SM2", "e32": "Cifrar 32 B", "d32": "Descifrar 32 B",
        "kx": "Intercambio de claves SM2", "kx1": "Un intercambio completo",
        "s_sm3": "SM3 1 MiB (MB/s)", "s_enc": "Cifrado SM4-CBC 1 MiB (MB/s)",
        "s_dec": "Descifrado SM4-CBC 1 MiB (MB/s)", "s_ks": "Expansión de clave SM4 (µs)",
        "s_keygen": "Generación de claves SM2 (µs)", "s_sign": "Firma SM2 (µs)", "s_verify": "Verificación SM2 (µs)",
        "s_e32": "Cifrado SM2 32 B (µs)", "s_d32": "Descifrado SM2 32 B (µs)",
        "s_kx": "Intercambio de claves SM2 (µs)", "lang": "Lenguaje",
        "sm4_cols": ["Cifrado 1 MiB (MB/s)", "Descifrado 1 MiB (MB/s)", "Expansión de clave (µs)"],
    },
}[LANG]


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


def ratio(b, a, digits=2):
    if b is None or a is None:
        return "—"
    r = b / a
    return f"**{r:.{digits}f}×**" if r >= 1 else f"{r:.2f}×"


LANGS = [("c", "C"), ("rust", "Rust"), ("go", "Go"), ("csharp", "C#"), ("java", "Java"),
         ("javascript", "JavaScript"), ("python", "Python"), ("swift", "Swift")]
REFS = [(k, n) for k, n in [("openssl-3.0.13", "OpenSSL 3.0.13"), ("openssl-3.6.5", "OpenSSL 3.6.5"),
                            ("bc", "BouncyCastle 1.86")] if k in data]
VARIANTS = [v for v in ("new", "perf") if any(f"{k}-{v}" in data for k, _ in LANGS)]


def table(title, unit, ops):
    print(f"\n### {title}（{unit}）\n" if LANG == "zh" else f"\n### {title} ({unit})\n")
    print(f"| {T['impl']} | " + " | ".join(h for _, h in ops) + " |")
    print("|---|" + "---|" * len(ops))
    for k, n in REFS:
        print(f"| {n} | " + " | ".join(fmt(o, us(k, o)) for o, _ in ops) + " |")
    for k, n in LANGS:
        print(f"| {n} {T['base']} | " + " | ".join(fmt(o, us(f"{k}-base", o)) for o, _ in ops) + " |")
        for v in VARIANTS:
            cells = []
            for o, _ in ops:
                b, a = us(f"{k}-base", o), us(f"{k}-{v}", o)
                sep = "（" if LANG == "zh" else " ("
                end = "）" if LANG == "zh" else ")"
                cells.append("—" if b is None or a is None else f"{fmt(o, a)}{sep}{ratio(b, a)}{end}")
            print(f"| {n} `{T[v]}` | " + " | ".join(cells) + " |")


SUMMARY = [("sm3/1MB", "s_sm3"), ("sm4/cbc_encrypt/1MB", "s_enc"), ("sm4/cbc_decrypt/1MB", "s_dec"),
           ("sm4/key_schedule", "s_ks"), ("sm2/keygen", "s_keygen"), ("sm2/sign", "s_sign"),
           ("sm2/verify", "s_verify"), ("sm2/encrypt/32B", "s_e32"), ("sm2/decrypt/32B", "s_d32"),
           ("sm2/key_exchange", "s_kx")]


def summary():
    """1) main next to the references, 2) SM4 across the three versions, 3) main's speed-up over the old code."""
    main = VARIANTS[-1]
    refs = [(k, n) for k, n in REFS if k != "openssl-3.0.13"]
    print(f"| {T['op']} | " + " | ".join(n for _, n in refs + LANGS) + " |")
    print("|---|" + "---|" * (len(refs) + len(LANGS)))
    for o, key in SUMMARY:
        cells = [fmt(o, us(k, o)) for k, _ in refs] + [fmt(o, us(f"{k}-{main}", o)) for k, _ in LANGS]
        print(f"| {T[key]} | " + " | ".join(cells) + " |")

    sides = ["base"] + VARIANTS
    print(f"\n| {T['lang']} | " + " | ".join(T["sm4_cols"]) + " |")
    print("|---|---|---|---|")
    for k, n in LANGS:
        cells = []
        for o in ("sm4/cbc_encrypt/1MB", "sm4/cbc_decrypt/1MB", "sm4/key_schedule"):
            vals = [fmt(o, us(f"{k}-{s}", o)) for s in sides]
            vals[-1] = f"**{vals[-1]}**"
            cells.append(" / ".join(vals))
        print(f"| {n} | " + " | ".join(cells) + " |")

    print(f"\n| {T['op']} | " + " | ".join(n for _, n in LANGS) + " |")
    print("|---|" + "---|" * len(LANGS))
    for o, key in SUMMARY:
        cells = [ratio(us(f"{k}-base", o), us(f"{k}-{main}", o), 1) for k, _ in LANGS]
        label = T[key].split("（")[0].split(" (")[0]
        print(f"| {label} | " + " | ".join(cells) + " |")


if SUMMARY_MODE:
    summary()
    sys.exit()

table(T["sm3"], T["mbs"], [("sm3/64B", "64 B"), ("sm3/1KB", "1 KiB"), ("sm3/1MB", "1 MiB")])
table(T["enc"], T["mbs"], [("sm4/cbc_encrypt/16B", "16 B"), ("sm4/cbc_encrypt/1KB", "1 KiB"),
                           ("sm4/cbc_encrypt/1MB", "1 MiB")])
table(T["dec"], T["mbs"], [("sm4/cbc_decrypt/16B", "16 B"), ("sm4/cbc_decrypt/1KB", "1 KiB"),
                           ("sm4/cbc_decrypt/1MB", "1 MiB")])
table(T["ks"], T["us"], [("sm4/key_schedule", T["setkey"])])
table(T["sm2a"], T["us"], [("sm2/keygen", T["keygen"]), ("sm2/sign", T["sign"]), ("sm2/verify", T["verify"])])
table(T["sm2b"], T["us"], [("sm2/encrypt/32B", T["e32"]), ("sm2/decrypt/32B", T["d32"])])
table(T["kx"], T["kx_unit"], [("sm2/key_exchange", T["kx1"])])
