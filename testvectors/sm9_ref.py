#!/usr/bin/env python3
"""Plain, slow reference implementation of SM9 (GB/T 38635), used only to make test vectors.

Everything is written with Python integers, ``hashlib`` (SM3) and the OpenSSL command
line (SM4-ECB). Nothing here imports the SMX library, so the vectors it produces are an
independent check of every language implementation. Not constant time; never use it
for real keys.

Representation (the same as GB/T 38635.5, chapter 2):
  Fq2  = Fq[u]  / (u^2 + 2)
  Fq4  = Fq2[v] / (v^2 - u)
  Fq12 = Fq4[w] / (w^3 - v)
Internally Fq12 is kept as six Fq2 coefficients of 1, w, ..., w^5 with w^6 = u, so
Fq4 element c_i = x_i + x_{i+3} v for i = 0, 1, 2.
Byte strings always put the high component first:
  Fq2   a1 || a0
  Fq12  c2 || c1 || c0, each Fq4 c_i as (x_{i+3}) || (x_i)
  G1    04 || x || y
  G2    04 || x1 || x0 || y1 || y0
"""

from __future__ import annotations

import hashlib
import subprocess

Q = 0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D
N = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25
T = 0x600000000058F98A
B = 5
P1 = (
    0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD,
    0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616,
)
# G2 coordinates as (a0, a1) = a0 + a1*u. The standard prints (a1, a0).
P2 = (
    (
        0x3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B,
        0x85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141,
    ),
    (
        0xA7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7,
        0x17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96,
    ),
)
assert N == 36 * T**4 + 36 * T**3 + 18 * T**2 + 6 * T + 1
assert Q == 36 * T**4 + 36 * T**3 + 24 * T**2 + 6 * T + 1


# ---------------------------------------------------------------- Fq2
def f2(a0, a1=0):
    return (a0 % Q, a1 % Q)


F2_ZERO = (0, 0)
F2_ONE = (1, 0)


def f2_add(a, b):
    return ((a[0] + b[0]) % Q, (a[1] + b[1]) % Q)


def f2_sub(a, b):
    return ((a[0] - b[0]) % Q, (a[1] - b[1]) % Q)


def f2_neg(a):
    return ((-a[0]) % Q, (-a[1]) % Q)


def f2_mul(a, b):
    # (a0 + a1 u)(b0 + b1 u) = a0 b0 - 2 a1 b1 + (a0 b1 + a1 b0) u
    return ((a[0] * b[0] - 2 * a[1] * b[1]) % Q, (a[0] * b[1] + a[1] * b[0]) % Q)


def f2_mul_fq(a, k):
    return (a[0] * k % Q, a[1] * k % Q)


def f2_mul_u(a):
    # (a0 + a1 u) u = -2 a1 + a0 u
    return ((-2 * a[1]) % Q, a[0])


def f2_conj(a):
    return (a[0], (-a[1]) % Q)


def f2_inv(a):
    # 1/(a0 + a1 u) = (a0 - a1 u) / (a0^2 + 2 a1^2)
    norm = (a[0] * a[0] + 2 * a[1] * a[1]) % Q
    inv = pow(norm, Q - 2, Q)
    return (a[0] * inv % Q, (-a[1]) * inv % Q)


def f2_pow(a, e):
    r = F2_ONE
    for bit in bin(e)[2:]:
        r = f2_mul(r, r)
        if bit == "1":
            r = f2_mul(r, a)
    return r


def f2_is_zero(a):
    return a[0] == 0 and a[1] == 0


# ---------------------------------------------------------------- Fq12 (w^6 = u)
F12_ONE = (F2_ONE,) + (F2_ZERO,) * 5


def f12_mul(x, y):
    acc = [F2_ZERO] * 11
    for i in range(6):
        if f2_is_zero(x[i]):
            continue
        for j in range(6):
            if f2_is_zero(y[j]):
                continue
            acc[i + j] = f2_add(acc[i + j], f2_mul(x[i], y[j]))
    return tuple(f2_add(acc[k], f2_mul_u(acc[k + 6])) if k < 5 else acc[k] for k in range(6))


def f12_conj6(x):
    # x^(q^6): w^(q^6) = -w, and Fq2 is fixed by q^6.
    return tuple(c if k % 2 == 0 else f2_neg(c) for k, c in enumerate(x))


def f12_inv(x):
    # x * x^(q^6) lies in Fq6 = Fq2[s] / (s^3 - u) with s = w^2.
    c = f12_conj6(x)
    m = f12_mul(x, c)
    assert all(f2_is_zero(m[k]) for k in (1, 3, 5))
    a0, a1, a2 = m[0], m[2], m[4]
    # Inverse in Fq2[s]/(s^3 - u).
    t0 = f2_sub(f2_mul(a0, a0), f2_mul_u(f2_mul(a1, a2)))
    t1 = f2_sub(f2_mul_u(f2_mul(a2, a2)), f2_mul(a0, a1))
    t2 = f2_sub(f2_mul(a1, a1), f2_mul(a0, a2))
    norm = f2_add(f2_mul(a0, t0), f2_mul_u(f2_add(f2_mul(a2, t1), f2_mul(a1, t2))))
    ni = f2_inv(norm)
    inv6 = (f2_mul(t0, ni), F2_ZERO, f2_mul(t1, ni), F2_ZERO, f2_mul(t2, ni), F2_ZERO)
    return f12_mul(c, inv6)


def f12_pow(x, e):
    r = F12_ONE
    for bit in bin(e)[2:]:
        r = f12_mul(r, r)
        if bit == "1":
            r = f12_mul(r, x)
    return r


_FROB_GAMMA = {}


def f12_frob(x, k):
    """x^(q^k): coefficient c_j w^j -> c_j^(q^k) w^j gamma_k^j, gamma_k = u^((q^k-1)/6)."""
    if k not in _FROB_GAMMA:
        _FROB_GAMMA[k] = f2_pow((0, 1), (Q**k - 1) // 6)
    g = _FROB_GAMMA[k]
    out = []
    gj = F2_ONE
    for j in range(6):
        c = x[j] if k % 2 == 0 else f2_conj(x[j])
        out.append(f2_mul(c, gj))
        gj = f2_mul(gj, g)
    return tuple(out)


def f12_to_bytes(x):
    # Fq12 = c2 w^2 + c1 w + c0 with c_i = x_i + x_{i+3} v; high component first.
    out = b""
    for i in (2, 1, 0):
        for coef in (x[i + 3], x[i]):
            out += coef[1].to_bytes(32, "big") + coef[0].to_bytes(32, "big")
    return out


# ---------------------------------------------------------------- G1 (affine, None = O)
def g1_on_curve(p):
    x, y = p
    return 0 <= x < Q and 0 <= y < Q and (y * y - x * x * x - B) % Q == 0


def g1_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0]:
        if (p[1] + q[1]) % Q == 0:
            return None
        lam = 3 * p[0] * p[0] * pow(2 * p[1], Q - 2, Q) % Q
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], Q - 2, Q) % Q
    x = (lam * lam - p[0] - q[0]) % Q
    return (x, (lam * (p[0] - x) - p[1]) % Q)


def g1_mul(k, p):
    r = None
    for bit in bin(k)[2:]:
        r = g1_add(r, r)
        if bit == "1":
            r = g1_add(r, p)
    return r


def g1_to_bytes(p):
    return b"\x04" + p[0].to_bytes(32, "big") + p[1].to_bytes(32, "big")


def g1_xy(p):
    return p[0].to_bytes(32, "big") + p[1].to_bytes(32, "big")


# ---------------------------------------------------------------- G2 on twist E': y^2 = x^3 + 5u
B_TWIST = (0, 5)


def g2_on_curve(p):
    x, y = p
    if not all(0 <= c < Q for c in (*x, *y)):
        return False
    return f2_sub(f2_mul(y, y), f2_add(f2_mul(f2_mul(x, x), x), B_TWIST)) == F2_ZERO


def g2_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0]:
        if f2_is_zero(f2_add(p[1], q[1])):
            return None
        lam = f2_mul(f2_mul_fq(f2_mul(p[0], p[0]), 3), f2_inv(f2_mul_fq(p[1], 2)))
    else:
        lam = f2_mul(f2_sub(q[1], p[1]), f2_inv(f2_sub(q[0], p[0])))
    x = f2_sub(f2_sub(f2_mul(lam, lam), p[0]), q[0])
    return (x, f2_sub(f2_mul(lam, f2_sub(p[0], x)), p[1]))


def g2_neg(p):
    return (p[0], f2_neg(p[1]))


def g2_mul(k, p):
    r = None
    for bit in bin(k)[2:]:
        r = g2_add(r, r)
        if bit == "1":
            r = g2_add(r, p)
    return r


def g2_to_bytes(p):
    (x0, x1), (y0, y1) = p
    return b"\x04" + b"".join(v.to_bytes(32, "big") for v in (x1, x0, y1, y0))


def g2_xy(p):
    return g2_to_bytes(p)[1:]


assert g1_on_curve(P1)
assert g2_on_curve(P2), "P2 is not on y^2 = x^3 + 5u"

# psi: E' -> E(Fq12), (x', y') -> (x' w^-2, y' w^-3). Frobenius on the twist:
#   pi(x', y') = (conj(x') * u^(-(q-1)/3), conj(y') * u^(-(q-1)/2)).
_PI_X = f2_inv(f2_pow((0, 1), (Q - 1) // 3))
_PI_Y = f2_inv(f2_pow((0, 1), (Q - 1) // 2))


def g2_frob(p):
    return (f2_mul(f2_conj(p[0]), _PI_X), f2_mul(f2_conj(p[1]), _PI_Y))


# ---------------------------------------------------------------- R-ate pairing
def _line(lam, t, p):
    """Line through the untwisted T with slope lam*w^-1, at P, multiplied by w^3 (in Fq4,
    so the final exponentiation removes it): (y' - lam x') + (lam xP) w^2 - yP w^3."""
    xt, yt = t
    c0 = f2_sub(yt, f2_mul(lam, xt))
    c2 = f2_mul_fq(lam, p[0])
    c3 = ((-p[1]) % Q, 0)
    return (c0, F2_ZERO, c2, c3, F2_ZERO, F2_ZERO)


def _dbl_step(t, p):
    lam = f2_mul(f2_mul_fq(f2_mul(t[0], t[0]), 3), f2_inv(f2_mul_fq(t[1], 2)))
    return _line(lam, t, p), g2_add(t, t)


def _add_step(t, q, p):
    if t[0] == q[0]:
        if f2_is_zero(f2_add(t[1], q[1])):
            # Vertical line x - xT: lies in Fq6 after scaling, removed by the final exponentiation.
            return F12_ONE, None
        return _dbl_step(t, p)
    lam = f2_mul(f2_sub(q[1], t[1]), f2_inv(f2_sub(q[0], t[0])))
    return _line(lam, t, p), g2_add(t, q)


def final_exp(f):
    f = f12_mul(f12_conj6(f), f12_inv(f))  # f^(q^6 - 1)
    f = f12_mul(f12_frob(f, 2), f)  # f^(q^2 + 1)
    return f12_pow(f, (Q**4 - Q**2 + 1) // N)


def pairing(p, q):
    """e(P, Q) with P in G1, Q in G2: R-ate with a = 6t + 2 (GB/T 38635.1, B.6.2)."""
    if p is None or q is None:
        return F12_ONE
    a = 6 * T + 2
    f = F12_ONE
    t = q
    for bit in bin(a)[3:]:
        line, t = _dbl_step(t, p)
        f = f12_mul(f12_mul(f, f), line)
        if bit == "1":
            line, t = _add_step(t, q, p)
            f = f12_mul(f, line)
    q1 = g2_frob(q)
    q2 = g2_frob(q1)
    line, t = _add_step(t, q1, p)
    f = f12_mul(f, line)
    line, t = _add_step(t, g2_neg(q2), p)
    f = f12_mul(f, line)
    return final_exp(f)


# ---------------------------------------------------------------- hashes
def sm3(data: bytes) -> bytes:
    return hashlib.new("sm3", data).digest()


def kdf(z: bytes, klen: int) -> bytes:
    out = b""
    ct = 1
    while len(out) < klen:
        out += sm3(z + ct.to_bytes(4, "big"))
        ct += 1
    return out[:klen]


def _h(tag: int, z: bytes, n: int = N) -> int:
    hlen = 8 * ((5 * n.bit_length() + 31) // 32)  # 320 bits for 256-bit n
    assert hlen == 320
    ha = b""
    ct = 1
    while len(ha) * 8 < hlen:
        ha += sm3(bytes([tag]) + z + ct.to_bytes(4, "big"))
        ct += 1
    ha = ha[: hlen // 8]
    return int.from_bytes(ha, "big") % (n - 1) + 1


def h1(z: bytes) -> int:
    return _h(1, z)


def h2(z: bytes) -> int:
    return _h(2, z)


def sm4_ecb(key: bytes, data: bytes, decrypt: bool = False) -> bytes:
    args = ["openssl", "enc", "-sm4-ecb", "-K", key.hex(), "-nosalt"]
    if decrypt:
        args.append("-d")
    return subprocess.run(args, input=data, capture_output=True, check=True).stdout


# ---------------------------------------------------------------- SM9
def inv_n(x):
    return pow(x, N - 2, N)


def sign_user_key(ks, uid: bytes, hid: int):
    t1 = (h1(uid + bytes([hid])) + ks) % N
    assert t1 != 0
    return g1_mul(ks * inv_n(t1) % N, P1)


def enc_user_key(ke, uid: bytes, hid: int):
    t1 = (h1(uid + bytes([hid])) + ke) % N
    assert t1 != 0
    return g2_mul(ke * inv_n(t1) % N, P2)


def sign(msg: bytes, ds, ppub_s, r: int):
    g = pairing(P1, ppub_s)
    w = f12_pow(g, r)
    h = h2(msg + f12_to_bytes(w))
    l_val = (r - h) % N
    assert l_val != 0
    s = g1_mul(l_val, ds)
    return h.to_bytes(32, "big") + g1_to_bytes(s)


def verify(msg: bytes, sig: bytes, uid: bytes, hid: int, ppub_s) -> bool:
    if len(sig) != 97 or sig[32] != 4:
        return False
    h = int.from_bytes(sig[:32], "big")
    if not 1 <= h <= N - 1:
        return False
    s = (int.from_bytes(sig[33:65], "big"), int.from_bytes(sig[65:], "big"))
    if not g1_on_curve(s):
        return False
    g = pairing(P1, ppub_s)
    t = f12_pow(g, h)
    p = g2_add(g2_mul(h1(uid + bytes([hid])), P2), ppub_s)
    u = pairing(s, p)
    w = f12_mul(u, t)
    return h2(msg + f12_to_bytes(w)) == h


def q_of(uid: bytes, hid: int, ppub_e):
    return g1_add(g1_mul(h1(uid + bytes([hid])), P1), ppub_e)


def encapsulate(uid: bytes, hid: int, ppub_e, klen: int, r: int):
    c = g1_mul(r, q_of(uid, hid, ppub_e))
    w = f12_pow(pairing(ppub_e, P2), r)
    k = kdf(g1_xy(c) + f12_to_bytes(w) + uid, klen)
    assert any(k)
    return k, g1_to_bytes(c)


def decapsulate(c, uid: bytes, de, klen: int):
    w = pairing(c, de)
    return kdf(g1_xy(c) + f12_to_bytes(w) + uid, klen)


MAC_KEY_LEN = 32
SM4_KEY_LEN = 16


def encrypt(msg: bytes, uid: bytes, hid: int, ppub_e, r: int, block: bool):
    c1 = g1_mul(r, q_of(uid, hid, ppub_e))
    w = f12_pow(pairing(ppub_e, P2), r)
    z = g1_xy(c1) + f12_to_bytes(w) + uid
    if block:
        k = kdf(z, SM4_KEY_LEN + MAC_KEY_LEN)
        k1, k2 = k[:SM4_KEY_LEN], k[SM4_KEY_LEN:]
        assert any(k1)
        c2 = sm4_ecb(k1, msg)
    else:
        k = kdf(z, len(msg) + MAC_KEY_LEN)
        k1, k2 = k[: len(msg)], k[len(msg) :]
        assert any(k1)
        c2 = bytes(a ^ b for a, b in zip(msg, k1))
    c3 = sm3(c2 + k2)
    return g1_to_bytes(c1) + c3 + c2


def decrypt(ct: bytes, uid: bytes, de, block: bool):
    c1 = (int.from_bytes(ct[1:33], "big"), int.from_bytes(ct[33:65], "big"))
    assert ct[0] == 4 and g1_on_curve(c1)
    c3, c2 = ct[65:97], ct[97:]
    w = pairing(c1, de)
    z = g1_xy(c1) + f12_to_bytes(w) + uid
    if block:
        k = kdf(z, SM4_KEY_LEN + MAC_KEY_LEN)
        k1, k2 = k[:SM4_KEY_LEN], k[SM4_KEY_LEN:]
    else:
        k = kdf(z, len(c2) + MAC_KEY_LEN)
        k1, k2 = k[: len(c2)], k[len(c2) :]
    assert any(k1)
    if sm3(c2 + k2) != c3:
        return None
    if block:
        return sm4_ecb(k1, c2, decrypt=True)
    return bytes(a ^ b for a, b in zip(c2, k1))


def exchange(id_a: bytes, id_b: bytes, hid: int, ppub_e, de_a, de_b, ra: int, rb: int, klen: int):
    """Both sides of the key exchange. Returns every intermediate value."""
    r_a = g1_mul(ra, q_of(id_b, hid, ppub_e))
    r_b = g1_mul(rb, q_of(id_a, hid, ppub_e))
    # B
    g1 = pairing(r_a, de_b)
    g2 = f12_pow(pairing(ppub_e, P2), rb)
    g3 = f12_pow(g1, rb)
    gb = [f12_to_bytes(v) for v in (g1, g2, g3)]
    tail = id_a + id_b + g1_xy(r_a) + g1_xy(r_b)
    sk_b = kdf(tail + gb[0] + gb[1] + gb[2], klen)
    inner = sm3(gb[1] + gb[2] + tail)
    sb = sm3(b"\x82" + gb[0] + inner)
    s2 = sm3(b"\x83" + gb[0] + inner)
    # A
    g1a = f12_pow(pairing(ppub_e, P2), ra)
    g2a = pairing(r_b, de_a)
    g3a = f12_pow(g2a, ra)
    ga = [f12_to_bytes(v) for v in (g1a, g2a, g3a)]
    inner_a = sm3(ga[1] + ga[2] + tail)
    s1 = sm3(b"\x82" + ga[0] + inner_a)
    sk_a = kdf(tail + ga[0] + ga[1] + ga[2], klen)
    sa = sm3(b"\x83" + ga[0] + inner_a)
    assert s1 == sb and sa == s2 and sk_a == sk_b
    return {
        "RA": g1_to_bytes(r_a),
        "RB": g1_to_bytes(r_b),
        "SK": sk_a,
        "SB": sb,
        "SA": sa,
        "g1": gb[0],
        "g2": gb[1],
        "g3": gb[2],
    }
