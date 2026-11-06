#!/usr/bin/env python3
"""Checks compiled code for the branches an optimizer can introduce into constant-time paths.

LLVM can turn masked table scans into compare-and-branch code, so reading the Rust proves nothing.
Usage, for x86-64 or arm64, default profile and LTO alike (the bench binary contains all paths):

    cargo bench --bench sm_bench --no-run
    objdump -d --no-show-raw-insn -C target/release/deps/sm_bench-<hash> > out.asm
    python3 tools/check_ct_asm.py out.asm

Repeat with CARGO_PROFILE_BENCH_LTO=fat CARGO_PROFILE_BENCH_CODEGEN_UNITS=1. Exit status 0 means:
- both table scans load all 16 entries with no branch anywhere in the scan, as a loop or unrolled;
- the functions that must be branch-free have no conditional branch other than allowed ones.
SM4's block cipher is not checked: on this branch it uses secret-indexed lookup tables and is not
meant to be constant time (the `security` branch keeps the constant-time SM4 and its S-box check).
Only SM4's padding check is still held to the rule.
Branches elsewhere in the scalar multiplications are listed by `--list` for reading; they must
only depend on public data (window index, scalar bit position, table building).

The scan and `modinv` rules describe the code shapes of opt-level 3 and LTO. At opt-level s, z, 1
and 2 the shapes differ (nested limb loops, helper calls), so a FAIL there means: read `--list` and
the loop bodies. The other functions are checked at every level.
"""
import re
import sys

COND = re.compile(r"^(j(?!mp)[a-z]+|b\.[a-z]{2}|cbn?z|tbn?z)\b")
# Allowed conditional branches: public loop counters and lengths, by function.
BRANCH_FREE = {
    r"field::reduce_wide_p": 0,
    r"order::redc": 0,
    r"Jacobian>?::double": 0,
    r"Jacobian>?::add_mixed_raw": 0,
    r"sm4::pkcs7_check": 1,  # the public length check
    r"modinv::invert": 2,  # the fixed 59- and 10-iteration counters
    r"hex::encode_scalar": 2,  # the loop over the public length
    r"hex::decode_scalar": 2,  # the loop over the public length
}
SCAN_HOSTS = r"scalar_mul::mul_(base|ct)\b|ECPoint>?::multiply\b"


def functions(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    seen = {}
    for block in re.split(r"\n(?=[0-9a-f]+ <)", text):
        head = re.match(r"[0-9a-f]+ <(.*)>:", block.strip())
        if not head or head.group(1) in seen:
            continue
        lines = []
        for line in block.strip().split("\n")[1:]:
            parsed = re.match(r"\s*([0-9a-f]+):\s*(.*)", line)
            if parsed:
                lines.append((int(parsed.group(1), 16), parsed.group(2).strip()))
        seen[head.group(1)] = lines
    return seen


def target(text):
    found = re.search(r"(?:0x)?([0-9a-f]+)\s*<", text)
    return int(found.group(1), 16) if found else None


def loop_scans(lines):
    """x86 and arm scan loops: (stride, end, branch-free body) for counted loops with mask work."""
    index = {address: i for i, (address, _) in enumerate(lines)}
    scans = []
    for i, (_, text) in enumerate(lines):
        if not COND.match(text) or target(text) not in index or index[target(text)] >= i:
            continue
        body = lines[index[target(text)] : i + 1]
        if len(body) > 90:
            continue
        code = "\n".join(t for _, t in body)
        stride = re.search(
            r"(?:add\s+\$0x(40|60),%r\w+|add\s+x\d+, x\d+, #(64|96)|\[x\d+\], #(64|96))", code
        )
        # A counted end, or LLVM's scaled down-counter closing a post-indexed loop (cbnz).
        end = re.search(r"cmp\s+\$0x(400|600|658),%r\w+|cmp\s+x\d+, #(1024|1536)", code)
        if not stride or not (end or text.startswith("cbnz")):
            continue
        inner = [t for _, t in body[:-1] if COND.match(t) or re.match(r"(jmp|b\s|call|bl\s)", t)]
        masked = re.search(r"\bpand\b|and\.16b|\band\b", code) is not None
        size = int(stride.group(1), 16) if stride.group(1) else int(stride.group(2) or stride.group(3))
        scans.append((size, not inner and masked))
    return scans


def unrolled_scans(lines):
    """arm: a straight run of `ldp q, q, [xN, #off]` covering the whole 1024-byte table."""
    found = []
    runs = {}
    for _, text in lines:
        if COND.match(text) or re.match(r"(b\s|bl\s|ret)", text):
            for base, offsets in runs.items():
                if set(range(0, 1024, 32)) <= offsets:
                    found.append(base)
            runs = {}
            continue
        load = re.match(r"ldp\s+q\d+, q\d+, \[(x\d+)(?:, #(\d+))?\]", text)
        if load:
            runs.setdefault(load.group(1), set()).add(int(load.group(2) or 0))
    return found


def main():
    funcs = functions(sys.argv[1])
    errors = []
    seen_branch_free = 0
    for pattern, allowed in BRANCH_FREE.items():
        for name, lines in funcs.items():
            if re.search(pattern, name):
                seen_branch_free += 1
                count = sum(1 for _, t in lines if COND.match(t))
                if count > allowed:
                    errors.append(f"{name}: {count} conditional branches, {allowed} allowed")
    if not seen_branch_free:
        errors.append("no branch-free function found: wrong binary or symbols stripped")

    hosts = {n: l for n, l in funcs.items() if re.search(SCAN_HOSTS, n)}
    good_base = good_variable = False
    for name, lines in hosts.items():
        for stride, clean in loop_scans(lines):
            if not clean:
                errors.append(f"{name}: scan loop of stride {stride} contains a branch")
            good_base |= clean and stride == 64
            good_variable |= clean and stride == 96
        good_base |= bool(unrolled_scans(lines))
    if not good_base:
        errors.append("fixed-base table scan not recognized as a complete branch-free scan")
    if not good_variable:
        errors.append("variable-base table scan not recognized as a complete branch-free scan")

    if "--list" in sys.argv:
        for name, lines in hosts.items():
            print("==", name)
            for i, (_, text) in enumerate(lines):
                if COND.match(text):
                    print("  " + " | ".join(t[:34] for _, t in lines[max(0, i - 2) : i + 1]))

    for error in errors:
        print("FAIL:", error)
    print("FAIL" if errors else "PASS")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
