#!/usr/bin/env python3
"""Generate ``smx/_sm4_core.py``, the SM4 S-box as a Boolean circuit without tables.

Run ``python tools/gen_sm4_sbox.py`` and then ``ruff format smx/_sm4_core.py``.

The S-box is S(x) = A(I(A(x) + C)) + C, where I inverts in GF(2^8) modulo
x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1, A is the circular matrix with first row
0xD3 and C = 0xD3. This script moves the inversion into the tower field
GF(((2^2)^2)^2), where it only takes AND and XOR gates, tries every tower
isomorphism and keeps the one with the fewest gates. The output is checked against
the standard S-box for all 256 inputs before it is written.
"""

from __future__ import annotations

from itertools import product
from pathlib import Path

POLY = 0x1F5
AFFINE_ROW = 0xD3
AFFINE_CONST = 0xD3
# GB/T 32907-2016, used only to check the circuit.
STANDARD_SBOX = bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c052b679a762abe04c3aa44132649860699"
    "9c4250f491ef987a33540b43edcfac62e4b31ca9c908e89580df94fa758f3fa6"
    "4707a7fcf37317ba83593c19e6854fa8686b81b27164da8bf8eb0f4b70569d35"
    "1e240e5e6358d1a225227c3b01217887d40046579fd327524c3602e7a0c4c89e"
    "eabf8ad240c738b5a3f7f2cef96115a1e0ae5da49b341a55ad933230f58cb1e3"
    "1df6e22e8266ca60c02923ab0d534e6fd5db3745defd8e2f03ff6a726d6c5b51"
    "8d1baf92bbddbc7f11d95c411f105ad80ac13188a5cd7bbd2d74d012b8e5b4b0"
    "8969974a0c96777e65b9f109c56ec68418f07dec3adc4d2079ee5f3ed7cb3948"
)


def gf_mul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= POLY
        b >>= 1
    return result


def gf_inv(a: int) -> int:
    result = 1
    for _ in range(254):
        result = gf_mul(result, a)
    return result if a else 0


def affine_matrix() -> list[int]:
    """Rows of A, most significant output bit first, as 8-bit masks."""
    return [((AFFINE_ROW >> i) | (AFFINE_ROW << (8 - i))) & 0xFF for i in range(8)]


def apply_affine(x: int) -> int:
    output = 0
    for row in affine_matrix():
        output = output << 1 | (bin(row & x).count("1") & 1)
    return output


def formula_sbox(x: int) -> int:
    return apply_affine(gf_inv(apply_affine(x) ^ AFFINE_CONST)) ^ AFFINE_CONST


class Circuit:
    """Straight-line XOR/AND program with common subexpression elimination."""

    def __init__(self, inputs: list[str]) -> None:
        self.lines: list[str] = []
        self.known: dict[tuple[str, str, str], str] = {}
        self.count = 0
        self.inputs = inputs

    def gate(self, op: str, a: str, b: str) -> str:
        key = (op, *sorted((a, b)))
        name = self.known.get(key)
        if name is None:
            name = f"t{self.count}"
            self.count += 1
            self.known[key] = name
            self.lines.append(f"{name} = {a} {op} {b}")
        return name

    def xor(self, a: str, b: str) -> str:
        return self.gate("^", a, b)

    def and_(self, a: str, b: str) -> str:
        return self.gate("&", a, b)


def xor4(c, a, b):  # GF(2^2) addition
    return [c.xor(x, y) for x, y in zip(a, b)]


def mul4(c, a, b):
    """(a1 w + a0)(b1 w + b0) with w^2 = w + 1; values are [high, low]."""
    low = c.and_(a[1], b[1])
    both = c.and_(c.xor(a[0], a[1]), c.xor(b[0], b[1]))
    return [c.xor(both, low), c.xor(c.and_(a[0], b[0]), low)]


def square4(c, a):
    return [a[0], c.xor(a[0], a[1])]


def scale_w(c, a):
    """Multiply by w: (a1 w + a0) w = (a1 + a0) w + a1."""
    return [c.xor(a[0], a[1]), a[0]]


def scale_w2(c, a):
    """Multiply by w^2 = w + 1: (a1 w + a0)(w + 1) = a0 w + (a1 + a0)."""
    return [a[1], c.xor(a[0], a[1])]


LAMBDA_SCALERS = {2: scale_w, 3: scale_w2}


def mul16(c, a, b, lam):
    high, low = a[:2], a[2:]
    b_high, b_low = b[:2], b[2:]
    low_product = mul4(c, low, b_low)
    high_product = mul4(c, high, b_high)
    both = mul4(c, xor4(c, high, low), xor4(c, b_high, b_low))
    # (A1 z + A0)(B1 z + B0) with z^2 = z + lam
    new_high = xor4(c, both, low_product)
    new_low = xor4(c, LAMBDA_SCALERS[lam](c, high_product), low_product)
    return new_high + new_low


def square16(c, a, lam):
    high, low = a[:2], a[2:]
    high_square = square4(c, high)
    return high_square + xor4(c, square4(c, low), LAMBDA_SCALERS[lam](c, high_square))


def inv16(c, a, lam):
    high, low = a[:2], a[2:]
    sum_ = xor4(c, high, low)
    norm = xor4(
        c,
        LAMBDA_SCALERS[lam](c, square4(c, high)),
        xor4(c, mul4(c, high, low), square4(c, low)),
    )
    norm_inv = square4(c, norm)
    return mul4(c, high, norm_inv) + mul4(c, sum_, norm_inv)


def scale16(c, a, nu, lam):
    """Multiply by a constant of GF(2^4) using only XOR gates."""
    columns = []
    for bit in range(4):
        basis = [0, 0, 0, 0]
        basis[bit] = 1
        columns.append(_mul16_value(_bits_value(basis), nu, lam))
    outputs: list[str | None] = [None, None, None, None]
    for row in range(4):
        for col in range(4):
            if columns[col] >> (3 - row) & 1:
                outputs[row] = (
                    a[col] if outputs[row] is None else c.xor(outputs[row], a[col])
                )
    return outputs


def _bits_value(bits):
    value = 0
    for bit in bits:
        value = value << 1 | bit
    return value


def _mul4_value(a, b):
    a1, a0, b1, b0 = a >> 1, a & 1, b >> 1, b & 1
    low = a0 & b0
    both = (a0 ^ a1) & (b0 ^ b1)
    return (both ^ low) << 1 | ((a1 & b1) ^ low)


def _mul16_value(a, b, lam):
    high, low, b_high, b_low = a >> 2, a & 3, b >> 2, b & 3
    low_product = _mul4_value(low, b_low)
    high_product = _mul4_value(high, b_high)
    both = _mul4_value(high ^ low, b_high ^ b_low)
    return (both ^ low_product) << 2 | (_mul4_value(lam, high_product) ^ low_product)


def _mul256_value(a, b, nu, lam):
    high, low, b_high, b_low = a >> 4, a & 15, b >> 4, b & 15
    low_product = _mul16_value(low, b_low, lam)
    high_product = _mul16_value(high, b_high, lam)
    both = _mul16_value(high ^ low, b_high ^ b_low, lam)
    return (both ^ low_product) << 4 | (
        _mul16_value(nu, high_product, lam) ^ low_product
    )


def inv256(c, a, nu, lam):
    high, low = a[:4], a[4:]
    sum_ = [c.xor(x, y) for x, y in zip(high, low)]
    high_scaled = scale16(c, square16(c, high, lam), nu, lam)
    product = mul16(c, high, low, lam)
    low_square = square16(c, low, lam)
    norm = [c.xor(c.xor(x, y), z) for x, y, z in zip(high_scaled, product, low_square)]
    norm_inv = inv16(c, norm, lam)
    return mul16(c, high, norm_inv, lam) + mul16(c, sum_, norm_inv, lam)


def invert_matrix(rows: list[int]) -> list[int] | None:
    """Invert an 8x8 GF(2) matrix; rows are masks, bit 7 is the first column."""
    work = [(rows[i] << 8) | (1 << (7 - i)) for i in range(8)]
    for col in range(8):
        pivot = next((r for r in range(col, 8) if work[r] >> (15 - col) & 1), None)
        if pivot is None:
            return None
        work[col], work[pivot] = work[pivot], work[col]
        for r in range(8):
            if r != col and work[r] >> (15 - col) & 1:
                work[r] ^= work[col]
    return [row & 0xFF for row in work]


def mat_mul(left: list[int], right: list[int]) -> list[int]:
    output = []
    for row in left:
        value = 0
        for col in range(8):
            if row >> (7 - col) & 1:
                value ^= right[col]
        output.append(value)
    return output


def paar(c: Circuit, rows: list[int], inputs: list[str], const: int) -> list[str]:
    """Build a linear layer with Paar's greedy shared-pair heuristic."""
    names = list(inputs)
    work = [{i for i in range(8) if row >> (7 - i) & 1} for row in rows]
    while True:
        counts: dict[tuple[int, int], int] = {}
        for row in work:
            items = sorted(row)
            for i, a in enumerate(items):
                for b in items[i + 1 :]:
                    counts[(a, b)] = counts.get((a, b), 0) + 1
        if not counts:
            break
        (a, b), _ = max(
            counts.items(), key=lambda item: (item[1], -item[0][0], -item[0][1])
        )
        names.append(c.xor(names[a], names[b]))
        new = len(names) - 1
        for row in work:
            if a in row and b in row:
                row.discard(a)
                row.discard(b)
                row.add(new)
    outputs = [names[next(iter(row))] for row in work]
    for i in range(8):
        if const >> (7 - i) & 1:
            outputs[i] = c.xor(outputs[i], "ones")
    return outputs


def tower_elements(lam: int, nu: int):
    """Yield the images in GF(2^8) of a basis of the tower for each isomorphism."""
    roots_w = [x for x in range(2, 256) if gf_mul(x, x) ^ x ^ 1 == 0]
    for w in roots_w:
        lam_value = {2: w, 3: w ^ 1}[lam]
        roots_z = [x for x in range(2, 256) if gf_mul(x, x) ^ x ^ lam_value == 0]
        for z in roots_z:
            nu_value = 0
            for i, part in enumerate(
                ((nu >> 3) & 1, (nu >> 2) & 1, (nu >> 1) & 1, nu & 1)
            ):
                basis = (gf_mul(w, z), z, w, 1)[i]
                if part:
                    nu_value ^= basis
            roots_y = [x for x in range(2, 256) if gf_mul(x, x) ^ x ^ nu_value == 0]
            for y in roots_y:
                yield [
                    gf_mul(gf_mul(w, z), y),
                    gf_mul(z, y),
                    gf_mul(w, y),
                    y,
                    gf_mul(w, z),
                    z,
                    w,
                    1,
                ]


def build(lam: int, nu: int, images: list[int]) -> Circuit | None:
    # Columns of M (tower -> field) are the images of the tower basis.
    tower_to_field = []
    for bit in range(7, -1, -1):
        row = 0
        for image in images:
            row = row << 1 | (image >> bit & 1)
        tower_to_field.append(row)
    field_to_tower = invert_matrix(tower_to_field)
    if field_to_tower is None:
        return None
    affine = affine_matrix()
    # Inputs b7..b0 feed the top layer: tower = M^-1 (A x + C).
    top = mat_mul(field_to_tower, affine)
    const_bits = 0
    for row in field_to_tower:
        const_bits = const_bits << 1 | (bin(row & AFFINE_CONST).count("1") & 1)
    bottom = mat_mul(affine, tower_to_field)
    inputs = [f"b{i}" for i in range(7, -1, -1)]
    circuit = Circuit(inputs)
    tower_input = paar(circuit, top, inputs, const_bits)
    tower_inverse = inv256(circuit, tower_input, nu, lam)
    outputs = paar(circuit, bottom, tower_inverse, AFFINE_CONST)
    circuit.outputs = outputs  # type: ignore[attr-defined]
    return circuit


def live_lines(circuit: Circuit) -> list[str]:
    """Drop gates that no output uses."""
    needed = set(circuit.outputs)  # type: ignore[attr-defined]
    kept = []
    for line in reversed(circuit.lines):
        name, _, a, _, b = line.split()
        if name in needed:
            kept.append(line)
            needed.update((a, b))
    return kept[::-1]


def evaluate(lines: list[str], outputs: list[str], x: int) -> int:
    values = {"ones": 1, **{f"b{i}": x >> i & 1 for i in range(8)}}
    for line in lines:
        name, _, a, op, b = line.split()
        values[name] = values[a] & values[b] if op == "&" else values[a] ^ values[b]
    result = 0
    for name in outputs:
        result = result << 1 | values[name]
    return result


def search() -> tuple[list[str], list[str]]:
    best = None
    for lam, nu in product((2, 3), range(1, 16)):
        # z^2 + z + nu is irreducible over GF(2^4) only for some nu.
        if any(_mul16_value(x, x, lam) ^ x ^ nu == 0 for x in range(16)):
            continue
        if any(_mul4_value(x, x) ^ x ^ lam == 0 for x in range(4)):
            continue
        for images in tower_elements(lam, nu):
            circuit = build(lam, nu, images)
            if circuit is None:
                continue
            lines = live_lines(circuit)
            if best is None or len(lines) < len(best[0]):
                outputs = circuit.outputs  # type: ignore[attr-defined]
                if all(
                    evaluate(lines, outputs, x) == formula_sbox(x) for x in range(256)
                ):
                    best = (lines, outputs)
    if best is None:
        raise SystemExit("no valid circuit found")
    return best


HEADER = '''"""SM4 S-box as a Boolean circuit. Generated by tools/gen_sm4_sbox.py; do not edit.

There is no table and no branch here, so no memory access depends on the data.
"""

from __future__ import annotations


def sub_bytes(x: int, ones: int) -> int:
    """Apply the S-box to every byte of x at once.

    ``ones`` has the lowest bit of every byte of x set. Each name holds one bit
    position of all the bytes, so one gate works on all of them.
    """
'''


def main() -> None:
    assert all(formula_sbox(x) == STANDARD_SBOX[x] for x in range(256))
    lines, outputs = search()
    assert all(evaluate(lines, outputs, x) == STANDARD_SBOX[x] for x in range(256))
    text = HEADER
    text += f"    # {len(lines)} gates: {sum('&' in line for line in lines)} AND, the rest XOR.\n"
    text += "    b0 = x & ones\n"
    for i in range(1, 8):
        text += f"    b{i} = x >> {i} & ones\n"
    text += "".join(f"    {line}\n" for line in lines)
    shifted = " | ".join(
        name if i == 7 else f"{name} << {7 - i}" for i, name in enumerate(outputs)
    )
    text += f"    return {shifted}\n"
    target = Path(__file__).resolve().parents[1] / "smx" / "_sm4_core.py"
    target.write_text(text)
    print(f"{len(lines)} gates")


if __name__ == "__main__":
    main()
