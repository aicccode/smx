#!/usr/bin/env python3
"""Generates sm4_sbox_circuit.inc: the SM4 S-box as a Boolean circuit.

Build-time tool only. The S-box is affine maps around inversion in GF(2^8):
    S(x) = post(inverse(pre(x)))
Inversion is computed in a tower field GF(((2^2)^2)^2), which needs only a few
dozen AND gates. The field and isomorphism with the fewest gates are searched for,
the result is checked here against the standard S-box on all 256 inputs, and
test_security.c checks the generated C again.

The output has no table and no branch: time and memory access cannot depend on
the input. Each gate acts on a 32-bit word, so 4 bytes are processed in parallel
(bit i of every byte lives in x<i>, at bit positions 0, 8, 16 and 24).

Usage: gen_sm4_circuit.py > sm4_sbox_circuit.inc
"""

SBOX = bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c052b679a762abe04c3aa441326498606999c4250f491ef987a33540b43edcfac62"
    "e4b31ca9c908e89580df94fa758f3fa64707a7fcf37317ba83593c19e6854fa8686b81b27164da8bf8eb0f4b70569d35"
    "1e240e5e6358d1a225227c3b01217887d40046579fd327524c3602e7a0c4c89eeabf8ad240c738b5a3f7f2cef96115a1"
    "e0ae5da49b341a55ad933230f58cb1e31df6e22e8266ca60c02923ab0d534e6fd5db3745defd8e2f03ff6a726d6c5b51"
    "8d1baf92bbddbc7f11d95c411f105ad80ac13188a5cd7bbd2d74d012b8e5b4b08969974a0c96777e65b9f109c56ec684"
    "18f07dec3adc4d2079ee5f3ed7cb3948"
)
assert len(SBOX) == 256

AES_POLY = 0x11B


def aes_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= AES_POLY
        b >>= 1
    return r


AES_INV = [0] * 256
for _a in range(1, 256):
    for _b in range(1, 256):
        if aes_mul(_a, _b) == 1:
            AES_INV[_a] = _b
            break

# Affine map into the AES inversion, found for SM4 by matching the fields.
_PRE_LO = bytes.fromhex("01077274e4e2979157512422b2b4c1c7")
_PRE_HI = bytes.fromhex("00a249eb09ab40e212b05bf91bb952f0")


def pre(x):
    return _PRE_LO[x & 15] ^ _PRE_HI[x >> 4]


_PRE_INV = {pre(x): x for x in range(256)}
assert len(_PRE_INV) == 256


def post(y):
    """post(y) = S(pre^-1(inverse(y)))"""
    return SBOX[_PRE_INV[AES_INV[y]]]


# ---- tower field on integers, used for the search ----


def gf4_mul(a, b):
    a1, a0, b1, b0 = a >> 1, a & 1, b >> 1, b & 1
    p = a0 & b0
    return (((a1 ^ a0) & (b1 ^ b0)) ^ p) << 1 | ((a1 & b1) ^ p)


def gf16_mul(a, b):
    a1, a0, b1, b0 = a >> 2, a & 3, b >> 2, b & 3
    p = gf4_mul(a0, b0)
    q = gf4_mul(a1, b1)
    phi_q = ((q >> 1) ^ (q & 1)) << 1 | (q >> 1)  # q * w
    return (gf4_mul(a1 ^ a0, b1 ^ b0) ^ p) << 2 | (phi_q ^ p)


def tower_mul(a, b, lam):
    a1, a0, b1, b0 = a >> 4, a & 15, b >> 4, b & 15
    p = gf16_mul(a0, b0)
    q = gf16_mul(a1, b1)
    return (gf16_mul(a1 ^ a0, b1 ^ b0) ^ p) << 4 | (gf16_mul(q, lam) ^ p)


def tower_pow_poly_root(beta, lam):
    """Evaluates the AES polynomial x^8 + x^4 + x^3 + x + 1 at beta."""
    pw = [1]
    for _ in range(8):
        pw.append(tower_mul(pw[-1], beta, lam))
    return pw[8] ^ pw[4] ^ pw[3] ^ pw[1] ^ pw[0]


def tower_field_ok(lam):
    """y^2 + y + lam must be irreducible over GF(16)."""
    return all(gf16_mul(y, y) ^ y ^ lam != 0 for y in range(16))


def matrix_of(f, c):
    """Columns of the linear part of an affine byte map."""
    cols = [f(1 << j) ^ c for j in range(8)]
    for x in range(256):
        v = 0
        for j in range(8):
            if x >> j & 1:
                v ^= cols[j]
        assert v == f(x) ^ c
    return cols


# ---- straight-line program ----


class Program:
    def __init__(self):
        self.lines = []
        self.memo = {}
        self.count = 0

    def gate(self, op, a, b):
        if a > b:
            a, b = b, a
        key = (op, a, b)
        if key in self.memo:
            return self.memo[key]
        name = f"t{self.count}"
        self.count += 1
        self.lines.append(f"    const uint32_t {name} = {a} {op} {b};")
        self.memo[key] = name
        return name

    def xor(self, a, b):
        return self.gate("^", a, b)

    def and_(self, a, b):
        return self.gate("&", a, b)

    def linear(self, cols, inputs):
        """Paar's greedy common-subexpression search for a binary matrix."""
        rows = []
        for i in range(8):
            rows.append({inputs[j] for j in range(8) if cols[j] >> i & 1})
        while True:
            pairs = {}
            for row in rows:
                items = sorted(row)
                for p in range(len(items)):
                    for q in range(p + 1, len(items)):
                        k = (items[p], items[q])
                        pairs[k] = pairs.get(k, 0) + 1
            if not pairs:
                break
            best = max(sorted(pairs), key=lambda k: pairs[k])
            name = self.xor(*best)
            for row in rows:
                if best[0] in row and best[1] in row:
                    row -= set(best)
                    row.add(name)
        return [next(iter(row)) for row in rows]

    # tower field on signals; elements are lists, most significant first

    def s4_mul(self, a, b):
        p = self.and_(a[1], b[1])
        hi = self.xor(self.and_(self.xor(a[0], a[1]), self.xor(b[0], b[1])), p)
        lo = self.xor(self.and_(a[0], b[0]), p)
        return [hi, lo]

    def s4_xor(self, a, b):
        return [self.xor(a[i], b[i]) for i in range(len(a))]

    def s4_times_w(self, q):
        return [self.xor(q[0], q[1]), q[0]]

    def s4_square(self, a):
        return [a[0], self.xor(a[0], a[1])]

    def s16_mul(self, a, b):
        a1, a0, b1, b0 = a[:2], a[2:], b[:2], b[2:]
        p = self.s4_mul(a0, b0)
        q = self.s4_mul(a1, b1)
        hi = self.s4_xor(self.s4_mul(self.s4_xor(a1, a0), self.s4_xor(b1, b0)), p)
        lo = self.s4_xor(self.s4_times_w(q), p)
        return hi + lo

    def s16_square(self, a):
        a1, a0 = a[:2], a[2:]
        s1 = self.s4_square(a1)
        s0 = self.s4_square(a0)
        # (a1 z + a0)^2 = a1^2 (z + w) + a0^2
        return s1 + self.s4_xor(self.s4_times_w(s1), s0)

    def s16_inv(self, a):
        a1, a0 = a[:2], a[2:]
        s = self.s4_xor(a1, a0)
        delta = self.s4_xor(self.s4_mul(a1, a0), self.s4_xor(self.s4_times_w(self.s4_square(a1)),
                                                              self.s4_square(a0)))
        di = self.s4_square(delta)  # the inverse in GF(4) is the square
        return self.s4_mul(a1, di) + self.s4_mul(s, di)

    def s16_scale(self, a, k):
        """a * k for a constant k in GF(16), as XORs only."""
        cols = [gf16_mul(1 << j, k) for j in range(4)]
        bits = a[::-1]
        out = []
        for i in range(4):
            terms = [bits[j] for j in range(4) if cols[j] >> i & 1]
            if not terms:
                return None
            r = terms[0]
            for t in terms[1:]:
                r = self.xor(r, t)
            out.append(r)
        return out[::-1]

    def s256_inv(self, a, lam):
        a1, a0 = a[:4], a[4:]
        s = self.s4_xor(a1, a0)
        delta = self.s4_xor(self.s16_mul(a1, a0),
                            self.s4_xor(self.s16_scale(self.s16_square(a1), lam),
                                        self.s16_square(a0)))
        di = self.s16_inv(delta)
        return self.s16_mul(a1, di) + self.s16_mul(s, di)


def build(lam, beta):
    def to_tower(y):
        r = 0
        pw = 1
        for i in range(8):
            if y >> i & 1:
                r ^= pw
            pw = tower_mul(pw, beta, lam)
        return r

    from_tower = {to_tower(y): y for y in range(256)}
    if len(from_tower) != 256:
        return None

    in_c = to_tower(pre(0))
    in_cols = matrix_of(lambda x: to_tower(pre(x)), in_c)
    out_c = post(from_tower[0])
    out_cols = matrix_of(lambda t: post(from_tower[t]), out_c)

    prog = Program()
    inputs = [f"x{j}" for j in range(8)]
    bits = prog.linear(in_cols, inputs)  # bits[i] is bit i
    flip_in = [in_c >> i & 1 for i in range(8)]
    named = []
    for i, b in enumerate(bits):
        if flip_in[i]:
            name = f"n{i}"
            prog.lines.append(f"    const uint32_t {name} = {b} ^ SM4_SBOX_ONES;")
            named.append(name)
        else:
            named.append(b)
    inv = prog.s256_inv(named[::-1], lam)[::-1]  # most significant first inside
    out = prog.linear(out_cols, inv)
    flip_out = [out_c >> i & 1 for i in range(8)]
    return prog, out, flip_out


def check(prog, out, flip_out):
    """Evaluates the generated statements directly."""
    env_code = "\n".join(line.replace("const uint32_t ", "").strip().rstrip(";")
                         for line in prog.lines)
    code = compile(env_code, "circuit", "exec")
    for x in range(256):
        env = {f"x{j}": (x >> j) & 1 for j in range(8)}
        env["SM4_SBOX_ONES"] = 1
        exec(code, {}, env)
        r = 0
        for i in range(8):
            r |= (env[out[i]] ^ flip_out[i]) << i
        assert r == SBOX[x], (x, r, SBOX[x])


def main():
    best = None
    for lam in range(1, 16):
        if not tower_field_ok(lam):
            continue
        for beta in range(2, 256):
            if tower_pow_poly_root(beta, lam) != 0:
                continue
            built = build(lam, beta)
            if built is None:
                continue
            if best is None or len(built[0].lines) < len(best[0].lines):
                best = built
    prog, out, flip_out = best
    check(prog, out, flip_out)
    ands = sum(" & " in line for line in prog.lines)
    print("/* Generated by tools/gen_sm4_circuit.py; do not edit. */")
    print(f"/* {len(prog.lines)} gates, of which {ands} AND. No tables, no branches. */")
    print("/* clang-format off */")
    print("#define SM4_SBOX_ONES 0x01010101u")
    print("static inline uint32_t sm4_sbox_circuit(uint32_t in) {")
    for j in range(8):
        print(f"    const uint32_t x{j} = (in >> {j}) & SM4_SBOX_ONES;")
    for line in prog.lines:
        print(line)
    print("    return " + "\n         | ".join(
        (f"(({out[i]} ^ SM4_SBOX_ONES) << {i})" if flip_out[i] else f"({out[i]} << {i})")
        for i in range(8)) + ";")
    print("}")
    print("/* clang-format on */")


if __name__ == "__main__":
    main()
