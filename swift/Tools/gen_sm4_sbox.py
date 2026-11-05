#!/usr/bin/env python3
"""Generates the Boolean circuit for the SM4 S-box used in Sources/GMSwift/SM4SBox.swift.

S(x) = A * inv(A * x + c) + c over GF(2^8) mod x^8+x^7+x^6+x^5+x^4+x^2+1. The inversion is moved into the tower
field GF((2^4)^2), where it needs only three GF(2^4) multiplications and a small GF(2^4) inversion. Every step is
checked against the standard S-box here, and GMSwiftTests checks the Swift result on all 256 inputs again.

Development tool only: the library does not depend on it. Usage: Tools/gen_sm4_sbox.py > SM4SBox.body
"""

SBOX_HEX = (
    "d690e9fecce13db716b614c228fb2c052b679a762abe04c3aa441326498606999c4250f491ef987a33540b43edcfac62"
    "e4b31ca9c908e89580df94fa758f3fa64707a7fcf37317ba83593c19e6854fa8686b81b27164da8bf8eb0f4b70569d35"
    "1e240e5e6358d1a225227c3b01217887d40046579fd327524c3602e7a0c4c89eeabf8ad240c738b5a3f7f2cef96115a1"
    "e0ae5da49b341a55ad933230f58cb1e31df6e22e8266ca60c02923ab0d534e6fd5db3745defd8e2f03ff6a726d6c5b51"
    "8d1baf92bbddbc7f11d95c411f105ad80ac13188a5cd7bbd2d74d012b8e5b4b08969974a0c96777e65b9f109c56ec684"
    "18f07dec3adc4d2079ee5f3ed7cb3948"
)
SBOX = bytes.fromhex(SBOX_HEX)
assert len(SBOX) == 256


def gf8_mul(a, b, poly=0x1F5):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= poly
        b >>= 1
    return result


def gf4_mul(a, b):
    result = 0
    for i in range(4):
        if (b >> i) & 1:
            result ^= a << i
    for i in range(6, 3, -1):
        if (result >> i) & 1:
            result ^= 0b10011 << (i - 4)
    return result


GF4_INV = [0] * 16
for a in range(1, 16):
    GF4_INV[a] = next(b for b in range(1, 16) if gf4_mul(a, b) == 1)


def apply_rows(rows, x):
    """rows[i] is a bitmask: output bit i is the XOR of the input bits in the mask."""
    return sum((bin(rows[i] & x).count("1") & 1) << i for i in range(len(rows)))


# A: row i (bit i of the output) is 0xA7 rotated left by i.
A = [((0xA7 << i) | (0xA7 >> (8 - i))) & 0xFF for i in range(8)]
C = 0xD3


def gf8_inv(x):
    if x == 0:
        return 0
    return next(y for y in range(1, 256) if gf8_mul(x, y) == 1)


assert all(apply_rows(A, gf8_inv(apply_rows(A, x) ^ C)) ^ C == SBOX[x] for x in range(256))

# Tower: GF(2^8) = GF(2^4)[z]/(z^2 + z + lam). An element is (hi << 4) | lo meaning hi*z + lo.
LAM = next(l for l in range(1, 16) if all(gf4_mul(v, v) ^ v ^ l for v in range(16)))


def tower_mul(a, b):
    a1, a0, b1, b0 = a >> 4, a & 15, b >> 4, b & 15
    t = gf4_mul(a1, b1)
    return ((gf4_mul(a1, b0) ^ gf4_mul(a0, b1) ^ t) << 4) | (gf4_mul(a0, b0) ^ gf4_mul(t, LAM))


def tower_inv(a):
    a1, a0 = a >> 4, a & 15
    d = GF4_INV[gf4_mul(gf4_mul(a1, a1), LAM) ^ gf4_mul(a1, a0) ^ gf4_mul(a0, a0)]
    return (gf4_mul(a1, d) << 4) | gf4_mul(a0 ^ a1, d)


# Isomorphism: the image of the generator x of GF(2^8) is a root of its minimal polynomial in the tower.
def tower_pow_matrix(root):
    images = []
    value = 1
    for _ in range(8):
        images.append(value)
        value = tower_mul(value, root)
    return images


def poly_at_root(root):
    value = 0
    power = 1
    for bit in range(9):
        if (0x1F5 >> bit) & 1:
            value ^= power
        power = tower_mul(power, root)
    return value


ROOT = next(r for r in range(2, 256) if poly_at_root(r) == 0)
IMAGES = tower_pow_matrix(ROOT)  # column j = image of x^j
TO_TOWER = [sum(((IMAGES[j] >> i) & 1) << j for j in range(8)) for i in range(8)]


def invert_rows(rows):
    n = len(rows)
    aug = [rows[i] | (1 << (n + i)) for i in range(n)]
    for col in range(n):
        pivot = next(r for r in range(col, n) if (aug[r] >> col) & 1)
        aug[col], aug[pivot] = aug[pivot], aug[col]
        for r in range(n):
            if r != col and (aug[r] >> col) & 1:
                aug[r] ^= aug[col]
    return [aug[i] >> n for i in range(n)]


def compose(outer, inner):
    """Rows of outer(inner(x))."""
    result = []
    for row in outer:
        value = 0
        for i in range(8):
            if (row >> i) & 1:
                value ^= inner[i]
        result.append(value)
    return result


FROM_TOWER = invert_rows(TO_TOWER)
INPUT = compose(TO_TOWER, A)
INPUT_CONST = apply_rows(TO_TOWER, C)
OUTPUT = compose(A, FROM_TOWER)
OUTPUT_CONST = C

assert all(
    apply_rows(OUTPUT, tower_inv(apply_rows(INPUT, x) ^ INPUT_CONST)) ^ OUTPUT_CONST == SBOX[x] for x in range(256)
)

# --- straight-line program over symbolic wires ---
lines = []
counter = [0]


def fresh(expr):
    name = f"t{counter[0]}"
    counter[0] += 1
    lines.append(f"let {name} = {expr}")
    return name


def x(a, b):
    return fresh(f"{a} ^ {b}")


def n(a, b):
    return fresh(f"{a} & {b}")


def inv_wire(a):
    return fresh(f"{a} ^ one")


def linear(rows, inputs, constant):
    """Paar's greedy common-XOR elimination."""
    targets = [{i for i in range(8) if (row >> i) & 1} for row in rows]
    wires = list(inputs)
    while True:
        counts = {}
        for target in targets:
            members = sorted(target)
            for i, a in enumerate(members):
                for b in members[i + 1:]:
                    counts[(a, b)] = counts.get((a, b), 0) + 1
        if not counts:
            break
        (a, b), best = max(counts.items(), key=lambda item: (item[1], -item[0][0], -item[0][1]))
        wires.append(x(wires[a], wires[b]))
        index = len(wires) - 1
        for target in targets:
            if a in target and b in target:
                target -= {a, b}
                target.add(index)
    out = []
    for i, target in enumerate(targets):
        wire = wires[next(iter(target))]
        out.append(inv_wire(wire) if (constant >> i) & 1 else wire)
    return out


def xor4(a, b):
    return [x(a[i], b[i]) for i in range(4)]


def mul2(a, b):
    """Karatsuba product of two 2-bit polynomials, three coefficients."""
    low = n(a[0], b[0])
    high = n(a[1], b[1])
    middle = n(x(a[0], a[1]), x(b[0], b[1]))
    return [low, x(x(middle, low), high), high]


def mul4(a, b):
    """GF(2^4) = GF(2)[y]/(y^4+y+1), two-level Karatsuba: 9 ANDs."""
    low = mul2(a[:2], b[:2])
    high = mul2(a[2:], b[2:])
    middle = mul2(xor2(a[:2], a[2:]), xor2(b[:2], b[2:]))
    cross = [x(x(middle[i], low[i]), high[i]) for i in range(3)]
    d = [low[0], low[1], x(low[2], cross[0]), cross[1], x(high[0], cross[2]), high[1], high[2]]
    # y^4 = y + 1, y^5 = y^2 + y, y^6 = y^3 + y^2
    return [x(d[0], d[4]), x(x(d[1], d[4]), d[5]), x(x(d[2], d[5]), d[6]), x(d[3], d[6])]


def xor2(a, b):
    return [x(a[0], b[0]), x(a[1], b[1])]


def linear_gf4(function, a):
    """A GF(2)-linear map on GF(2^4) as XORs of input wires."""
    columns = [function(1 << i) for i in range(4)]
    out = []
    for bit in range(4):
        members = [a[i] for i in range(4) if (columns[i] >> bit) & 1]
        value = members[0]
        for member in members[1:]:
            value = x(value, member)
        out.append(value)
    return out


def inv4(a):
    """GF(2^4) inversion from its algebraic normal form."""
    def anf(bit):
        coefficients = [(GF4_INV[v] >> bit) & 1 for v in range(16)]
        for i in range(4):
            for v in range(16):
                if v >> i & 1:
                    coefficients[v] ^= coefficients[v ^ (1 << i)]
        return [v for v in range(16) if coefficients[v]]

    products = {}

    def product(mask):
        if mask in products:
            return products[mask]
        low = mask & -mask
        rest = mask ^ low
        index = low.bit_length() - 1
        wire = a[index] if rest == 0 else n(product(rest), a[index])
        products[mask] = wire
        return wire

    out = []
    for bit in range(4):
        monomials = anf(bit)
        assert 0 not in monomials
        value = product(monomials[0])
        for mono in monomials[1:]:
            value = x(value, product(mono))
        out.append(value)
    return out


input_wires = [f"x{i}" for i in range(8)]
u = linear(INPUT, input_wires, INPUT_CONST)
a0, a1 = u[:4], u[4:]
scaled_square = linear_gf4(lambda v: gf4_mul(gf4_mul(v, v), LAM), a1)
a0_square = linear_gf4(lambda v: gf4_mul(v, v), a0)
delta = inv4(xor4(xor4(scaled_square, a0_square), mul4(a1, a0)))
b1 = mul4(a1, delta)
b0 = mul4(xor4(a0, a1), delta)
outputs = linear(OUTPUT, b0 + b1, OUTPUT_CONST)

# --- evaluate the generated program on every input, as a check on this generator itself ---
for value in range(256):
    env = {f"x{i}": (value >> i) & 1 for i in range(8)}
    env["one"] = 1
    for line in lines:
        name, expr = line[4:].split(" = ")
        env[name] = eval(expr, {}, env)
    assert sum(env[outputs[i]] << i for i in range(8)) == SBOX[value], value

print("\n".join("    " + line for line in lines))
print("    return (" + ", ".join(outputs) + ")")
import sys

print(f"// gates: {len(lines)} and: {sum(' & ' in l for l in lines)} lam={LAM} root={ROOT}", file=sys.stderr)
