#!/usr/bin/env python3
"""Checks the release build's machine code for secret-dependent branches in the constant-time paths.

LLVM has turned masked table scans (`entry & mask`, with the mask computed inline) into a compare and a branch that
skips the loads, so reading the Swift source proves nothing. This script builds with `swift build -c release`,
disassembles the objects, and fails if:

  - a table-scan function has any branch except its loop counter, or reads less than a full entry per iteration;
  - a function that must be branch-free has a conditional branch;
  - a scalar multiplication stops calling the scan functions, or has a conditional branch that compares two
    non-constant values (a loop counter compares with a constant, a table-scan leak compares with the digit),
    or has more conditional branches than expected.

It works on x86-64 (objdump) and arm64 (llvm-objdump, macOS). It checks branches and memory reads, which are what the
optimizer has broken; it cannot see microarchitectural effects. Usage: Tools/check_constant_time.py [--no-build] [--size]  (--size builds with -Osize)

SM9 (scalar multiplication, GT exponentiation, Miller loop, final exponentiation) is checked for carry-flag
branches on top of a branch budget, see SM9_SECRET.

SM4 is deliberately not checked: on this branch it uses secret-indexed T-table lookups for speed and is not
cache-timing resistant, so there is no table-free property to verify. The constant-time SM4 (Boolean-circuit S-box)
lives on the `security` branch. Everything listed below (SM2 field/point code, hex, PKCS#7 and UTF-8 checks) still is.
"""
import glob
import os
import platform
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# name -> bytes of table entry read per iteration
SCANS = {"scanTable8(": 64, "scanTable12(": 96}
BRANCH_FREE = [
    "opaqueMask(", "FpElement.multiply(", "FpElement.square()", "montgomeryMultiply(", "montgomerySquare(",
    "BigInt256.modMul(", "BigInt256.modSquare(",
]
# Secret bytes go through these. Their only branches may be loop or length control, never data.
DATA_LOOPS = {"pkcs7InvalidMask(": 2, "utf8InvalidMask(": 2, "Hex.encodeDigits(": 18, "Hex.decode(": 16}
# name -> maximum conditional branches. These loops accumulate and decide once at the end; a vectorizer adds length
# guards. A branch on loaded data (an early exit) shows up as a compare with a memory operand and fails the check.
SIMPLE_LOOPS = {
    "fillSelectionMasks(": 2, "constantTimeEquals(": 14, "constantTimeIsAllZero(": 12,
    "sm9ConstantTimeEquals(": 14, "sm9ConstantTimeIsAllZero": 12, "sm9ScanTable(": 14,
}
# name -> (functions it must call, maximum conditional branches including public loop counters and table setup)
MULTIPLIERS = {
    "JacobianPoint.multiplyGenerator(": (["fillSelectionMasks", "scanTable8"], 11),
    "JacobianPoint.multiplyConstantTime(": (["fillSelectionMasks", "scanTable12"], 22),
}
# SM9 secret paths: (name fragment, functions the group must call, maximum conditional branches over all matches).
# Field arithmetic is inlined into these, so on top of the budget every branch must be controlled by a compare or bit
# test against a constant (loop counters, Booth window indices, bits of the public t) or be a stack guard / overflow
# trap. LLVM's cmov-to-branch conversion once turned the borrow correction of modular subtraction into a jump on the
# carry flag here; such a branch has no compare before it and fails this check.
SM9_SECRET = [
    ("SM9Jacobian.multiplySecret(", ["fillSelectionMasks", "sm9ScanTable"], 64),
    ("SM9Pairing.powSecret(", ["fillSelectionMasks", "sm9ScanTable"], 40),
    ("SM9Pairing.millerLoop(", [], 12),
    ("SM9Pairing.finalExponentiation(", [], 10),
]
TRAP_BRANCHES = ("jo", "jno", "js", "jns", "b.vs", "b.vc")
ARM_COND = re.compile(r"^(b\.[a-z]+|cbz|cbnz|tbz|tbnz)$")
FLAG_SETTERS = re.compile(r"^(cmp|cmpq|cmpl|cmpb|cmpw|test|testq|testl|testb|testw|subs|adds|ands|cmn|tst|bt|btq|btl)$")


def run(command, **kwargs):
    return subprocess.run(command, check=True, stdout=subprocess.PIPE, universal_newlines=True, **kwargs).stdout


def disassemble(objects):
    if platform.system() == "Darwin":
        tool = ["xcrun", "llvm-objdump", "-dr", "--no-show-raw-insn"]
        text = "".join(run(tool + [path]) for path in objects)
    else:
        text = "".join(run(["objdump", "-dr", "--no-show-raw-insn", path]) for path in objects)
    return run(["swift", "demangle", "--simplified"], input=text)


def parse(text):
    """Returns {function name: [(address, mnemonic, operands)]}."""
    functions = {}
    current = None
    for line in text.split("\n"):
        header = re.match(r"^[0-9a-f]+ <(.*)>:$", line) or re.match(r"^([^\s0-9].*):$", line)
        if header:
            current = functions.setdefault(header.group(1), [])
            continue
        if current is None:
            continue
        relocation = re.match(r"^\s*[0-9a-f]+:\s+(?:R_X86_64_|ARM64_RELOC_)\S+\s+(.*)$", line)
        if relocation:
            current.append((current[-1][0] if current else 0, "reloc", relocation.group(1)))
            continue
        match = re.match(r"^\s*([0-9a-f]+):?\s+(\S+)\s*(.*)$", line)
        if match:
            current.append((int(match.group(1), 16), match.group(2), match.group(3)))
    return functions


def is_conditional(mnemonic):
    return (mnemonic.startswith("j") and mnemonic != "jmp" and mnemonic != "jmpq") or bool(ARM_COND.match(mnemonic))


def is_branch(mnemonic):  # "reloc" entries are annotations, not instructions
    return is_conditional(mnemonic) or mnemonic in ("jmp", "jmpq", "b", "br", "call", "callq", "bl", "blr")


def target(operands):
    match = re.search(r"\b(?:0x)?([0-9a-f]+)\b(?: <|$)", operands.split(",")[-1].strip())
    return int(match.group(1), 16) if match else None


def bytes_read(mnemonic, operands):
    """Bytes loaded by one instruction, for the common forms an optimizer emits in a scan loop."""
    if mnemonic.startswith(("ldp", "ldr", "ldur", "ld1")):
        register = operands.split(",")[0].strip()
        size = 16 if register.startswith("q") else 8 if register[0] in "xd" else 4
        return size * 2 if mnemonic.startswith("ldp") else size
    if "(" not in operands or mnemonic.startswith("lea"):
        return 0
    parts = operands.split(",")
    memory_is_destination = "(" in parts[-1] and "(" not in parts[0]
    if memory_is_destination and mnemonic.startswith("mov"):
        return 0
    if "xmm" in operands:
        return 16
    if "ymm" in operands:
        return 32
    return 8


def conditional_branches(body):
    return [item for item in body if is_conditional(item[1])]


def check_scan(name, body, entry_bytes, problems):
    backward = [item for item in conditional_branches(body) if (target(item[2]) or 0) <= item[0]]
    if len(backward) != 1:
        problems.append("%s: expected one loop branch, found %d" % (name, len(backward)))
        return
    end = backward[0][0]
    start = target(backward[0][2])
    loop = [item for item in body if start <= item[0] <= end]
    inner = [item for item in loop[:-1] if is_branch(item[1])]
    if inner:
        problems.append("%s: branch inside the scan loop: %s %s" % (name, inner[0][1], inner[0][2]))
    read = sum(bytes_read(item[1], item[2]) for item in loop)
    if read < entry_bytes:
        problems.append("%s: loop reads %d bytes per iteration, entry is %d" % (name, read, entry_bytes))
    # Anything else may only be the guard for an empty table, before the loop.
    late = [item for item in conditional_branches(body) if item[0] > end]
    if late:
        problems.append("%s: conditional branch after the loop: %s %s" % (name, late[0][1], late[0][2]))
    guards = [item for item in conditional_branches(body) if item[0] < start]
    if len(guards) > 1:
        problems.append("%s: %d conditional branches before the loop" % (name, len(guards)))
    return read


def check_simple_loop(name, body, limit, problems):
    branches = conditional_branches(body)
    if len(branches) > limit:
        problems.append("%s: %d conditional branches, limit %d" % (name, len(branches), limit))
    for index, item in enumerate(body):
        # The first instructions compare the (public) array lengths.
        if not is_conditional(item[1]) or is_stack_guard(body, index) or index < 10:
            continue
        setter = previous_flag_setter(body, index)
        if setter and ("(" in setter[2] or "[" in setter[2]) and "(%rsp)" not in setter[2]:
            problems.append("%s: branch on a value from memory: %s %s" % (name, setter[1], setter[2]))


def previous_flag_setter(body, index):
    for item in reversed(body[max(0, index - 12):index]):
        if FLAG_SETTERS.match(item[1]):
            return item
    return None


def is_stack_guard(body, index):
    return any("%fs:0x28" in item[2] or "___stack_chk_guard" in item[2] for item in body[max(0, index - 4):index])


FLAG_NEUTRAL = re.compile(r"^(mov|lea|push|pop|cmov|set|nop|xchg|reloc|vmov|movs|movz|movq|movd|movl|movb|movw|movabs|movups|movaps|movdqu|movdqa|bswap|ldr|ldp|str|stp|ldur|stur|csel|csinc|csinv|csneg|cset|csetm|adr|adrp)")


def flag_writer(body, index):
    """The instruction whose flags the branch at index reads: walk back over instructions that leave flags alone."""
    for item in reversed(body[max(0, index - 64):index]):
        if item[1] in ("reloc",) or FLAG_NEUTRAL.match(item[1]):
            continue
        return item
    return None


def check_sm9_branches(name, body, problems):
    """Every conditional branch must be controlled by a compare/test/bit test, by a loop counter (inc/dec, add/sub of
    a constant), or by a shift or mask with a constant (allocation size checks), or be a stack guard or an overflow
    trap. Flags produced by multi-limb arithmetic (adc/sbb, add/sub/neg of two registers) fail: that is the borrow
    correction of modular addition turned into a jump. Table selection happens in the non-inlined fillSelectionMasks
    and sm9ScanTable, so no digit compare is inlined here; compares of two registers are loop bounds."""
    for index, item in enumerate(body):
        if not is_conditional(item[1]) or item[1] in TRAP_BRANCHES or is_stack_guard(body, index):
            continue
        writer = flag_writer(body, index)
        if writer is None:
            problems.append("%s: branch at %x has no flag-setting instruction" % (name[:60], item[0]))
            continue
        mnemonic = writer[1]
        constant = any(part.strip().startswith(("$", "#")) for part in writer[2].split(","))
        if re.match(r"^(cmp|test|bt|tst|cmn|inc|dec)", mnemonic):
            continue
        if re.match(r"^(add|sub|shr|sar|shl|and|or|subs|adds|ands|lsr|asr|lsl)", mnemonic) and constant:
            continue
        problems.append("%s: branch at %x on flags of %s %s" % (name[:60], item[0], mnemonic, writer[2]))


def main():
    if "--no-build" not in sys.argv:
        command = ["swift", "build", "-c", "release"]
        if "--size" in sys.argv:
            command += ["-Xswiftc", "-Osize"]
        run(command, cwd=ROOT, stderr=subprocess.STDOUT)
    objects = glob.glob(os.path.join(ROOT, ".build", "release", "GMSwift.build", "*.o"))
    if not objects:
        sys.exit("no objects found; run swift build -c release")
    functions = parse(disassemble(sorted(objects)))
    problems = []

    def matching(fragment):
        return {name: body for name, body in functions.items() if fragment in name and body}

    for fragment, entry_bytes in SCANS.items():
        found = matching(fragment)
        if not found:
            problems.append("missing scan function %s (inlined?)" % fragment)
        for name, body in found.items():
            read = check_scan(name, body, entry_bytes, problems)
            print("scan   %-44s loop reads %s bytes, entry %d" % (name[:44], read, entry_bytes))

    for fragment in BRANCH_FREE:
        found = matching(fragment)
        for name, body in found.items():
            count = len(conditional_branches(body))
            print("nojump %-44s conditional branches %d" % (name[:44], count))
            if count:
                problems.append("%s: must be branch-free, has %d conditional branches" % (name, count))
    if not matching("opaqueMask("):
        problems.append("missing opaqueMask (inlined?)")

    for fragment, limit in list(SIMPLE_LOOPS.items()) + list(DATA_LOOPS.items()):
        found = matching(fragment)
        if not found:
            # arm64 -Osize drops local symbol names (the function becomes ltmp0), so it cannot be found by name.
            if "--size" in sys.argv and platform.system() == "Darwin":
                print("note   %s has no symbol in this build and was not checked" % fragment)
            else:
                problems.append("missing %s (inlined?)" % fragment)
        for name, body in found.items():
            check_simple_loop(name, body, limit, problems)
            print("loop   %-44s conditional branches %d" % (name[:44], len(conditional_branches(body))))

    for fragment, (calls, limit) in MULTIPLIERS.items():
        found = matching(fragment)
        if not found:
            problems.append("missing %s" % fragment)
        text = ""
        total = 0
        for name, body in found.items():
            text += " ".join(item[2] for item in body if item[1] in ("reloc", "call", "callq", "bl", "blr")) + " "
            branches = conditional_branches(body)
            total += len(branches)
            for index, item in enumerate(body):
                if not is_conditional(item[1]) or is_stack_guard(body, index):
                    continue
                setter = previous_flag_setter(body, index)
                if setter is None or not setter[1].startswith(("cmp", "cmn", "subs")):
                    continue
                operands = [part.strip() for part in setter[2].split(",")]
                if not any(part.startswith(("$", "#")) for part in operands):
                    problems.append(
                        "%s: conditional branch at %x compares two variables: %s %s"
                        % (name[:60], item[0], setter[1], setter[2]))
        print("scalar %-44s conditional branches %d (limit %d)" % (fragment[:44], total, limit))
        if total > limit:
            problems.append("%s: %d conditional branches, limit %d" % (fragment, total, limit))
        for call in calls:
            if call not in text:
                problems.append("%s: no longer calls %s" % (fragment, call))

    for fragment, calls, limit in SM9_SECRET:
        found = matching(fragment)
        if not found:
            problems.append("missing %s" % fragment)
        text = ""
        total = 0
        for name, body in found.items():
            text += " ".join(item[2] for item in body if item[1] in ("reloc", "call", "callq", "bl", "blr")) + " "
            total += len(conditional_branches(body))
            check_sm9_branches(name, body, problems)
        print("sm9    %-44s conditional branches %d (limit %d)" % (fragment[:44], total, limit))
        if total > limit:
            problems.append("%s: %d conditional branches, limit %d" % (fragment, total, limit))
        for call in calls:
            if call not in text:
                problems.append("%s: no longer calls %s" % (fragment, call))

    if problems:
        print("\nFAILED:")
        for problem in problems:
            print("  " + problem)
        return 1
    print("\nOK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
