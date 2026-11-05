#!/usr/bin/env python3
"""Reads compiled machine code for branches that could depend on secrets.

Source that is free of secret branches does not guarantee object code that is: an optimizer
may turn a masked table scan back into a compare and a branch that skips loads. So this
builds test_ct_asm.c with each compiler, optimization level and LTO, then checks every ct_*
function, and whatever it calls in the same binary:

  * no conditional jump goes forward. A forward jump is how a load gets skipped. The only
    conditional jumps left are the backward edges of loops over fixed counts.
  * no unconditional jump goes backward. Loops compile to a conditional jump at the bottom,
    so this appears when a block has been moved out of line: at commit 751d51f the scan in
    ec_mul_g became "cmp selected, index; jne back" with the loads after it and a jmp back,
    so that its conditional jump was backward, like a loop counter, and passed the first rule.

This is a shape test and cannot follow data. tools/check_ct_trace.sh is the check that actually
compares execution, on the platforms where it can run; this one also runs on arm64.

The scans must also read the whole table, so ct_comb_select and ct_var_select must contain a
loop, or enough loads to cover every entry when fully unrolled.

Exit status 0 if every configuration is clean. Usage: check_ct_asm.py [-v]
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

SOURCES = ["test_ct_asm.c", "sm3.c"]
# Stack protector checks are a forward branch on a public canary, so they stay out.
BASE = ["-std=c99", "-w", "-fno-stack-protector"]
# Bodies of well-known libc functions are not ours to inspect.
EXTERNAL = re.compile(r"(@plt|^_?mem(cpy|set|move|cmp)|^_?str|^_?__stack_chk|^_?free|^_?malloc)")
CONDITIONAL = re.compile(
    r"^(j(?!mp\b)[a-z]+|b\.[a-z]+|cbz|cbnz|tbz|tbnz)$"  # x86-64 and arm64
)
CALL = re.compile(r"^(call[a-z]*|bl)$")


def disassemble(path):
    tool = shutil.which("objdump")
    if tool is None:
        sys.exit("objdump not found")
    text = subprocess.check_output([tool, "-d", "--no-show-raw-insn", path], text=True)
    funcs, name = {}, None
    for line in text.splitlines():
        m = re.match(r"^[0-9a-fA-F]+ <(.+)>:", line)
        if m:
            name = m.group(1)
            funcs[name] = []
            continue
        m = re.match(r"^\s*([0-9a-fA-F]+):\s+(\S+)\s*(.*)", line)
        if m and name:
            funcs[name].append((int(m.group(1), 16), m.group(2), m.group(3)))
    return funcs


def target_of(args):
    """The first operand that is a bare or 0x-prefixed code address."""
    for token in re.split(r"[,\s]+", args):
        token = token.strip("#")
        if re.fullmatch(r"(0x)?[0-9a-fA-F]+", token) and len(token) >= 3:
            return int(token, 16)
    return None


# Tests of public loop counts, read by hand: the addition chains' n parameter when they stay
# out of line, and the end of fn_inv's walk over the digits of the public exponent.
PUBLIC_COUNT_GUARDS = {"fe_sqr_n": 1, "fn_mont_sqr_n": 1, "fn_inv": 1}
PUBLIC_LOOP_JUMPS = {"fe_sqr_n": 1, "fn_mont_sqr_n": 1, "fn_inv": 1}


def check_function(name, insns):
    problems = []
    allowed = PUBLIC_COUNT_GUARDS.get(strip_symbol(name).split(".")[0], 0)
    back_jumps = PUBLIC_LOOP_JUMPS.get(strip_symbol(name).split(".")[0], 0)
    for addr, op, args in insns:
        if op in ("jmp", "b"):
            target = target_of(args)
            start = insns[0][0]
            if target is not None and start <= target < addr:
                if back_jumps > 0:
                    back_jumps -= 1
                else:
                    problems.append(f"{name}: backward unconditional jump at {addr:x}: {op} {args}")
        if CONDITIONAL.match(op):
            target = target_of(args)
            if target is None:
                problems.append(f"{name}: cannot read the target of {op} {args}")
            elif target > addr:
                if allowed > 0:
                    allowed -= 1
                else:
                    problems.append(f"{name}: forward conditional jump at {addr:x}: {op} {args}")
    return problems


def strip_symbol(name):
    return name[1:] if name.startswith("_") else name


def callees(insns):
    """Calls, and jumps to another symbol, which is how a tail call looks."""
    found = set()
    for _, op, args in insns:
        if CALL.match(op) or op in ("jmp", "b"):
            m = re.search(r"<([^>+]+)>", args)
            if m:
                found.add(m.group(1))
    return found


def check_binary(path, verbose):
    funcs = disassemble(path)
    roots = [n for n in funcs if strip_symbol(n).startswith("ct_") and n != "ct_keep"]
    if len(roots) < 27:
        return [f"expected at least 27 ct_ functions, found {len(roots)}"], 0
    problems = []
    seen, stack = set(), list(roots)
    while stack:
        name = stack.pop()
        if name in seen or name not in funcs or EXTERNAL.search(name):
            continue
        seen.add(name)
        problems += check_function(name, funcs[name])
        stack += callees(funcs[name])

    for scan, entries in (("ct_comb_select", 16 * 8), ("ct_var_select", 16 * 12)):
        for name in seen:
            base = strip_symbol(name)
            if base.startswith(scan.replace("ct_", "ec_")):
                insns = funcs[name]
                has_loop = any(CONDITIONAL.match(op) for _, op, _ in insns)
                ands = sum(1 for _, op, a in insns if "(" in a or "[" in a)
                if not has_loop and ands < entries / 4:
                    problems.append(f"{name}: too few loads for {entries} table words")
                if verbose:
                    print(f"  {name}: {len(insns)} instructions, {ands} memory operands")
    return problems, len(seen)


def configurations():
    configs = []
    for cc in ("gcc", "clang"):
        if shutil.which(cc) is None:
            continue
        version = subprocess.check_output([cc, "--version"], text=True).lower()
        label = "apple-clang" if "apple" in version else cc
        for opt in ("-O2", "-O3"):
            configs.append((label, cc, [opt]))
            configs.append((label, cc, [opt, "-flto"]))
            configs.append((label, cc, [opt, "-DSMX_NO_SIMD"]))
            configs.append((label, cc, [opt, "-DSMX_NO_SIMD", "-DSMX_NO_INT128"]))
    return configs


def main():
    verbose = "-v" in sys.argv
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        done = set()
        for label, cc, flags in configurations():
            key = (label, tuple(flags))
            if key in done:
                continue
            done.add(key)
            out = os.path.join(tmp, "ct")
            subprocess.check_call([cc] + BASE + flags + ["-o", out] + SOURCES)
            problems, count = check_binary(out, verbose)
            status = "ok" if not problems else "FAILED"
            print(f"{label} {' '.join(flags)}: {count} functions, {status}")
            for p in problems[:20]:
                print("   ", p)
            failed += len(problems)
    if failed:
        print(f"check_ct_asm: {failed} problems")
        return 1
    print("check_ct_asm: no suspect jump in any secret-handling function")
    return 0


if __name__ == "__main__":
    sys.exit(main())
