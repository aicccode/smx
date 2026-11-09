"""SM9 fields: Fq2 helpers and the Fq12 group GT (exponentiation, Frobenius, bytes).

Representation (GB/T 38635 uses the tower Fq2 = Fq[u]/(u^2+2), Fq4 = Fq2[v]/(v^2-u),
Fq12 = Fq4[w]/(w^3-v)): an Fq12 element is a tuple of twelve integers, the
coefficients of 1, w, ..., w^11 with w^12 = -2. The Fq2 coefficient of w^k in the
standard's six-coefficient form is ``c[k] + c[k + 6] * u``, as u = w^6. Fq2 elements
outside Fq12 are pairs ``(a0, a1)`` meaning a0 + a1*u.

Timing: as for SM2 (see :mod:`smx._ec`), CPython integers give no constant-time
guarantee. Secret exponents use :func:`pow_secret`, a fixed window over signed odd
digits whose table is always read in full and whose sign is applied with masks, so no
branch or table index depends on the exponent. That raises the bar and does not make
the code constant-time.
"""

from __future__ import annotations

from ._sm9_fq12 import mul, mul_line, sqr

__all__ = ["mul", "mul_line", "sqr"]

Q = 0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D
N = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25
T = 0x600000000058F98A

Fq2 = tuple[int, int]
Fq12 = tuple[int, ...]

ONE: Fq12 = (1,) + (0,) * 11
GT_BYTES = 384

# ---------------------------------------------------------------- Fq2 (not hot paths)


def f2_mul(a: Fq2, b: Fq2) -> Fq2:
    return (a[0] * b[0] - 2 * a[1] * b[1]) % Q, (a[0] * b[1] + a[1] * b[0]) % Q


def f2_sqr(a: Fq2) -> Fq2:
    return (a[0] * a[0] - 2 * a[1] * a[1]) % Q, 2 * a[0] * a[1] % Q


def f2_add(a: Fq2, b: Fq2) -> Fq2:
    return (a[0] + b[0]) % Q, (a[1] + b[1]) % Q


def f2_sub(a: Fq2, b: Fq2) -> Fq2:
    return (a[0] - b[0]) % Q, (a[1] - b[1]) % Q


def f2_mul_u(a: Fq2) -> Fq2:
    return -2 * a[1] % Q, a[0]


def f2_conj(a: Fq2) -> Fq2:
    return a[0], -a[1] % Q


def f2_inv(a: Fq2) -> Fq2:
    """1/(a0 + a1 u) = (a0 - a1 u)/(a0^2 + 2 a1^2). Variable time; public values only."""
    inverse = pow((a[0] * a[0] + 2 * a[1] * a[1]) % Q, -1, Q)
    return a[0] * inverse % Q, -a[1] * inverse % Q


def f2_pow(a: Fq2, e: int) -> Fq2:
    result = (1, 0)
    for bit in bin(e)[2:]:
        result = f2_sqr(result)
        if bit == "1":
            result = f2_mul(result, a)
    return result


# ---------------------------------------------------------------- Fq12 basics


def _coefficient(x: Fq12, k: int) -> Fq2:
    return x[k], x[k + 6]


def _from_coefficients(coefficients: list[Fq2]) -> Fq12:
    return tuple(c[0] for c in coefficients) + tuple(c[1] for c in coefficients)


def conj(x: Fq12) -> Fq12:
    """x^(q^6): w maps to -w. In the cyclotomic subgroup this is the inverse."""
    c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11 = x
    q = Q
    return c0, q - c1, c2, q - c3, c4, q - c5, c6, q - c7, c8, q - c9, c10, q - c11


def _gammas(power: int) -> tuple[Fq2, ...]:
    """gamma^j for j = 0..5 with gamma = u^((q^power - 1)/6)."""
    gamma = f2_pow((0, 1), (Q**power - 1) // 6)
    values = [(1, 0)]
    for _ in range(5):
        values.append(f2_mul(values[-1], gamma))
    return tuple(values)


_FROBENIUS = {power: _gammas(power) for power in (1, 2, 3)}


def frobenius(x: Fq12, power: int) -> Fq12:
    """x^(q^power) for power 1, 2 or 3: c_j w^j -> conj^power(c_j) gamma^j w^j."""
    q = Q
    gammas = _FROBENIUS[power]
    low = []
    high = []
    for j in range(6):
        a, b = x[j], x[j + 6]
        if power & 1:
            b = -b
        g0, g1 = gammas[j]
        low.append((a * g0 - 2 * b * g1) % q)
        high.append((a * g1 + b * g0) % q)
    return tuple(low + high)


def inverse(x: Fq12) -> Fq12:
    """1/x through the norm to Fq6 = Fq2[s]/(s^3 - u), s = w^2. Variable time.

    It is used once per pairing on the Miller loop output; the cost of the variable
    time Fq inversion does not depend on secret exponents.
    """
    c = conj(x)
    m = mul(x, c)  # lies in Fq6: only even powers of w
    a0, a1, a2 = _coefficient(m, 0), _coefficient(m, 2), _coefficient(m, 4)
    t0 = f2_sub(f2_sqr(a0), f2_mul_u(f2_mul(a1, a2)))
    t1 = f2_sub(f2_mul_u(f2_sqr(a2)), f2_mul(a0, a1))
    t2 = f2_sub(f2_sqr(a1), f2_mul(a0, a2))
    norm = f2_add(f2_mul(a0, t0), f2_mul_u(f2_add(f2_mul(a2, t1), f2_mul(a1, t2))))
    ni = f2_inv(norm)
    zero = (0, 0)
    inverse6 = [f2_mul(t0, ni), zero, f2_mul(t1, ni), zero, f2_mul(t2, ni), zero]
    return mul(c, _from_coefficients(inverse6))


def cyclotomic_sqr(x: Fq12) -> Fq12:
    """Square an element of the cyclotomic subgroup (Granger and Scott, 2010).

    With x = a + b w + c w^2 over Fq4 (w^3 = v), x^2 = (3a^2 - 2 conj(a))
    + (3 v c^2 + 2 conj(b)) w + (3 b^2 - 2 conj(c)) w^2, conj being v -> -v.
    a = (c0 + c6 u) + (c3 + c9 u) v, b uses c1 c7 c4 c10, c uses c2 c8 c5 c11.
    """
    c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11 = x
    q = Q
    # a^2 = (p^2 + u r^2) + 2 p r v with p = c0 + c6 u, r = c3 + c9 u.
    p0p0, p1p1, p0p1 = c0 * c0, c6 * c6, c0 * c6
    r0r0, r1r1, r0r1 = c3 * c3, c9 * c9, c3 * c9
    a_lo0 = p0p0 - 2 * p1p1 - 4 * r0r1
    a_lo1 = 2 * p0p1 + r0r0 - 2 * r1r1
    a_hi0 = 2 * (c0 * c3 - 2 * c6 * c9)
    a_hi1 = 2 * (c0 * c9 + c6 * c3)
    # b^2 with p = c1 + c7 u, r = c4 + c10 u.
    p0p0, p1p1, p0p1 = c1 * c1, c7 * c7, c1 * c7
    r0r0, r1r1, r0r1 = c4 * c4, c10 * c10, c4 * c10
    b_lo0 = p0p0 - 2 * p1p1 - 4 * r0r1
    b_lo1 = 2 * p0p1 + r0r0 - 2 * r1r1
    b_hi0 = 2 * (c1 * c4 - 2 * c7 * c10)
    b_hi1 = 2 * (c1 * c10 + c7 * c4)
    # c^2 with p = c2 + c8 u, r = c5 + c11 u.
    p0p0, p1p1, p0p1 = c2 * c2, c8 * c8, c2 * c8
    r0r0, r1r1, r0r1 = c5 * c5, c11 * c11, c5 * c11
    c_lo0 = p0p0 - 2 * p1p1 - 4 * r0r1
    c_lo1 = 2 * p0p1 + r0r0 - 2 * r1r1
    c_hi0 = 2 * (c2 * c5 - 2 * c8 * c11)
    c_hi1 = 2 * (c2 * c11 + c8 * c5)
    # v (c_lo + c_hi v) = u c_hi + c_lo v, and u (h0 + h1 u) = -2 h1 + h0 u.
    return (
        (3 * a_lo0 - 2 * c0) % q,
        (3 * -2 * c_hi1 + 2 * c1) % q,
        (3 * b_lo0 - 2 * c2) % q,
        (3 * a_hi0 + 2 * c3) % q,
        (3 * c_lo0 - 2 * c4) % q,
        (3 * b_hi0 + 2 * c5) % q,
        (3 * a_lo1 - 2 * c6) % q,
        (3 * c_hi0 + 2 * c7) % q,
        (3 * b_lo1 - 2 * c8) % q,
        (3 * a_hi1 + 2 * c9) % q,
        (3 * c_lo1 - 2 * c10) % q,
        (3 * b_hi1 + 2 * c11) % q,
    )


def to_bytes(x: Fq12) -> bytes:
    """384 bytes: c2 || c1 || c0 over Fq4, each Fq4 as b || a, each Fq2 as a1 || a0."""
    order = []
    for i in (2, 1, 0):
        order += (x[i + 9], x[i + 3], x[i + 6], x[i])
    value = 0
    for coefficient in order:
        value = value << 256 | coefficient
    return value.to_bytes(GT_BYTES, "big")


# ---------------------------------------------------------------- exponentiation

_WINDOW = 5
_WINDOW_COUNT = 52  # 260 bits, enough for k + n < 2**257
_WINDOW_MASK = (1 << _WINDOW) - 1
_TABLE_SIZE = 1 << (_WINDOW - 1)  # x^1, x^3, ..., x^31
_INDEX_MASK = _TABLE_SIZE - 1
_RECODE_OFFSET = (1 << (_WINDOW * _WINDOW_COUNT)) - 1


def recode(k: int, order: int) -> int:
    """Return A with k' = 2A - (2**260 - 1), k' being k or k + order, whichever is odd.

    In base 32, A has digits a_i with d_i = 2 a_i - 31 odd and non-zero and
    k' = sum(d_i 32^i). Shared by the GT and the curve fixed-window routines.
    """
    # Multiplying by 1 or 2 rather than 0 or 1, because CPython returns early for 0.
    return (k + order * ((~k & 1) + 1) - order + _RECODE_OFFSET) >> 1


def select_levels(lane_bits: int) -> tuple:
    """Masks for :func:`select` on a table of 16 lanes of ``lane_bits`` bits."""
    return tuple(
        (
            level,
            lane_bits << level,
            (1 << ((lane_bits << level) - 1), (1 << (lane_bits << level)) - 1),
        )
        for level in range(_WINDOW - 2, -1, -1)
    )


def select(table: int, index: int, levels: tuple) -> int:
    """Return lane ``index``, reading every lane and every mask for any index.

    Each level halves the table with one bit of the index; both masks of a level are
    always used, only the halves they apply to differ (as in :mod:`smx._ec`).
    """
    for level, half_bits, masks in levels:
        bit = index >> level & 1
        table = (table & masks[1 - bit]) | (table >> half_bits & masks[bit])
    return table


# A GT lane is 1 || c11 || ... || c0, 256 bits per coefficient. The set top bit keeps
# every selected value the same size.
_GT_LANE_BITS = 12 * 256 + 1
_GT_SENTINEL = 1 << (12 * 256)
_GT_LEVELS = select_levels(_GT_LANE_BITS)
_ODD_SLOTS = sum(((1 << 256) - 1) << (256 * i) for i in range(1, 12, 2))
_EVEN_SLOTS = sum(((1 << 256) - 1) << (256 * i) for i in range(0, 12, 2))
_Q_ODD = sum(Q << (256 * i) for i in range(1, 12, 2))
# Keep or drop a value of up to 12*256 bits; both masks have the same size.
_SIGN_MASKS = (_GT_SENTINEL, (_GT_SENTINEL << 1) - 1)
_COEFFICIENT_MASK = (1 << 256) - 1


def _pack(x: Fq12) -> int:
    value = _GT_SENTINEL
    for i, coefficient in enumerate(x):
        value |= coefficient << (256 * i)
    return value


def _unpack(lane: int) -> Fq12:
    data = (lane ^ _GT_SENTINEL).to_bytes(12 * 32, "little")
    return tuple(
        int.from_bytes(data[32 * i : 32 * i + 32], "little") for i in range(12)
    )


def odd_powers_table(x: Fq12) -> int:
    """Pack x^1, x^3, ..., x^31 for :func:`pow_secret`; x must be in GT."""
    x2 = cyclotomic_sqr(x)
    powers = [x]
    for _ in range(_TABLE_SIZE - 1):
        powers.append(mul(powers[-1], x2))
    packed = 0
    for i, power in enumerate(powers):
        packed |= _pack(power) << (i * _GT_LANE_BITS)
    return packed


def _signed_lookup(table: int, digit: int) -> Fq12:
    """x^d for the odd digit d = 2*digit - 31, by masks only."""
    positive = digit >> (_WINDOW - 1)
    lane = select(table, (digit ^ (positive - 1)) & _INDEX_MASK, _GT_LEVELS)
    odd = lane & _ODD_SLOTS
    negated = _Q_ODD - odd  # Q - c in every odd slot; no borrow crosses a slot
    lane = (
        (lane & (_EVEN_SLOTS | _GT_SENTINEL))
        | (odd & _SIGN_MASKS[positive])
        | (negated & _SIGN_MASKS[1 - positive])
    )
    return _unpack(lane)


def pow_secret(table: int, k: int) -> Fq12:
    """x^k for a secret k in [1, n-1], x in GT given by :func:`odd_powers_table`.

    Every window costs five cyclotomic squarings and one multiplication, and the
    table is read in full each time. x^n = 1 is what makes the odd recoding valid.
    """
    digits = recode(k, N)
    top = _WINDOW * (_WINDOW_COUNT - 1)
    result = _signed_lookup(table, digits >> top)
    csqr = cyclotomic_sqr
    for shift in range(top - _WINDOW, -1, -_WINDOW):
        result = csqr(csqr(csqr(csqr(csqr(result)))))
        result = mul(result, _signed_lookup(table, digits >> shift & _WINDOW_MASK))
    return result


def pow_public(x: Fq12, k: int) -> Fq12:
    """x^k for x in GT and a public k >= 0. Variable time (sliding signed window)."""
    if k == 0:
        return ONE
    powers = [x]
    x2 = cyclotomic_sqr(x)
    for _ in range(_TABLE_SIZE - 1):
        powers.append(mul(powers[-1], x2))
    # Width-5 NAF digits, most significant first.
    digits = []
    while k:
        if k & 1:
            digit = k & 31
            if digit >= 16:
                digit -= 32
            k -= digit
        else:
            digit = 0
        digits.append(digit)
        k >>= 1
    result = None
    for digit in reversed(digits):
        if result is not None:
            result = cyclotomic_sqr(result)
        if digit:
            term = powers[digit >> 1] if digit > 0 else conj(powers[(-digit) >> 1])
            result = term if result is None else mul(result, term)
    return result


def _naf(k: int) -> list[int]:
    digits = []
    while k:
        digit = 2 - (k & 3) if k & 1 else 0
        k = (k - digit) >> 1
        digits.append(digit)
    return digits[::-1]


_T_NAF = _naf(T)


def _pow_t(x: Fq12) -> Fq12:
    """x^t for the public BN parameter t, x in the cyclotomic subgroup."""
    inverse_x = conj(x)
    result = x  # the leading NAF digit is 1
    for digit in _T_NAF[1:]:
        result = cyclotomic_sqr(result)
        if digit == 1:
            result = mul(result, x)
        elif digit == -1:
            result = mul(result, inverse_x)
    return result


def final_exponentiation(f: Fq12) -> Fq12:
    """f^((q^12 - 1)/n): easy part, then the BN hard part of Scott et al. (2009)."""
    f = mul(conj(f), inverse(f))  # f^(q^6 - 1)
    f = mul(frobenius(f, 2), f)  # f^(q^2 + 1), now in the cyclotomic subgroup
    ft = _pow_t(f)
    ft2 = _pow_t(ft)
    ft3 = _pow_t(ft2)
    y0 = mul(mul(frobenius(f, 1), frobenius(f, 2)), frobenius(f, 3))
    y1 = conj(f)
    y2 = frobenius(ft2, 2)
    y3 = conj(frobenius(ft, 1))
    y4 = conj(mul(ft, frobenius(ft2, 1)))
    y5 = conj(ft2)
    y6 = conj(mul(ft3, frobenius(ft3, 1)))
    t0 = mul(mul(cyclotomic_sqr(y6), y4), y5)
    t1 = mul(mul(y3, y5), t0)
    t0 = mul(t0, y2)
    t1 = cyclotomic_sqr(mul(cyclotomic_sqr(t1), t0))
    t0 = mul(t1, y1)
    t1 = mul(t1, y0)
    return mul(cyclotomic_sqr(t0), t1)
