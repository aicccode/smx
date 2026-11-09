"""SM9 R-ate pairing e: G1 x G2 -> GT (GB/T 38635.1, B.6.2), a = 6t + 2.

The Miller loop keeps T in Jacobian coordinates on the twist and evaluates each line
at P directly as a sparse Fq12 element. The reference evaluates the line through the
untwisted T with slope lam w^-1, times w^3:

    (y_T - lam x_T) + (lam x_P) w^2 - y_P w^3.

Here every line is further multiplied by an Fq2 value made of Jacobian coordinates,
which clears all denominators; the final exponentiation removes any factor from a
proper subfield, so the result is the same element of GT. The loop schedule depends
only on the public constant a, never on the points.
"""

from __future__ import annotations

from collections.abc import Sequence

from ._sm9_field import (
    ONE,
    Q,
    T,
    f2_conj,
    f2_inv,
    f2_mul,
    f2_pow,
    final_exponentiation,
    mul,
    mul_line,
    sqr,
)

_LOOP = 6 * T + 2
_LOOP_BITS = bin(_LOOP)[3:]

# Frobenius on the twist: pi(x, y) = (conj(x) u^(-(q-1)/3), conj(y) u^(-(q-1)/2)).
_PI_X = f2_inv(f2_pow((0, 1), (Q - 1) // 3))
_PI_Y = f2_inv(f2_pow((0, 1), (Q - 1) // 2))


def twist_frobenius(point: Sequence[int]) -> tuple:
    x0, x1, y0, y1 = point
    x = f2_mul(f2_conj((x0, x1)), _PI_X)
    y = f2_mul(f2_conj((y0, y1)), _PI_Y)
    return x[0], x[1], y[0], y[1]


def _double_step(t: tuple, xp: int, yp: int) -> tuple:
    """Return (2T, line coefficients l0 l2 l3 l6 l8 l9) for the tangent at T.

    With T = (X, Y, Z) and the line scaled by 2 Y Z^3:
    c0 = 2 Y^2 - 3 X^3, c2 = 3 X^2 Z^2 x_P, c3 = -2 Y Z Z^2 y_P.
    """
    x0, x1, y0, y1, z0, z1 = t
    q = Q
    a0, a1 = (x0 * x0 - 2 * x1 * x1) % q, 2 * x0 * x1 % q
    b0, b1 = (y0 * y0 - 2 * y1 * y1) % q, 2 * y0 * y1 % q
    c0, c1 = (b0 * b0 - 2 * b1 * b1) % q, 2 * b0 * b1 % q
    zz0, zz1 = (z0 * z0 - 2 * z1 * z1) % q, 2 * z0 * z1 % q
    d0, d1 = 4 * (x0 * b0 - 2 * x1 * b1) % q, 4 * (x0 * b1 + x1 * b0) % q
    e0, e1 = 3 * a0, 3 * a1
    x30 = (e0 * e0 - 2 * e1 * e1 - 2 * d0) % q
    x31 = (2 * e0 * e1 - 2 * d1) % q
    m0, m1 = d0 - x30, d1 - x31
    y30 = (e0 * m0 - 2 * e1 * m1 - 8 * c0) % q
    y31 = (e0 * m1 + e1 * m0 - 8 * c1) % q
    z30 = 2 * (y0 * z0 - 2 * y1 * z1) % q
    z31 = 2 * (y0 * z1 + y1 * z0) % q
    l0 = (2 * b0 - (e0 * x0 - 2 * e1 * x1)) % q
    l6 = (2 * b1 - (e0 * x1 + e1 * x0)) % q
    l2 = (e0 * zz0 - 2 * e1 * zz1) % q * xp % q
    l8 = (e0 * zz1 + e1 * zz0) % q * xp % q
    l3 = -((z30 * zz0 - 2 * z31 * zz1) % q) * yp % q
    l9 = -((z30 * zz1 + z31 * zz0) % q) * yp % q
    return (x30, x31, y30, y31, z30, z31), (l0, l2, l3, l6, l8, l9)


def _add_step(t: tuple, other: Sequence[int], xp: int, yp: int) -> tuple:
    """Return (T + R, line coefficients) for the line through T and affine R.

    With H = x_R Z^2 - X, S = y_R Z^3 - Y and Z3 = Z H, the line scaled by Z3 is
    c0 = Z3 y_R - S x_R, c2 = S x_P, c3 = -Z3 y_P. Returns line None for a vertical
    line, which the final exponentiation would remove anyway.
    """
    x0, x1, y0, y1, z0, z1 = t
    ax0, ax1, ay0, ay1 = other
    q = Q
    zz0, zz1 = (z0 * z0 - 2 * z1 * z1) % q, 2 * z0 * z1 % q
    zzz0, zzz1 = (zz0 * z0 - 2 * zz1 * z1) % q, (zz0 * z1 + zz1 * z0) % q
    h0 = (ax0 * zz0 - 2 * ax1 * zz1 - x0) % q
    h1 = (ax0 * zz1 + ax1 * zz0 - x1) % q
    r0 = (ay0 * zzz0 - 2 * ay1 * zzz1 - y0) % q
    r1 = (ay0 * zzz1 + ay1 * zzz0 - y1) % q
    if h0 == 0 and h1 == 0:  # never for points of G2 and this loop; kept for safety
        if r0 == 0 and r1 == 0:
            return _double_step(t, xp, yp)
        return (1, 0, 1, 0, 0, 0), None
    hh0, hh1 = (h0 * h0 - 2 * h1 * h1) % q, 2 * h0 * h1 % q
    hhh0, hhh1 = (hh0 * h0 - 2 * hh1 * h1) % q, (hh0 * h1 + hh1 * h0) % q
    v0, v1 = (x0 * hh0 - 2 * x1 * hh1) % q, (x0 * hh1 + x1 * hh0) % q
    x30 = (r0 * r0 - 2 * r1 * r1 - hhh0 - 2 * v0) % q
    x31 = (2 * r0 * r1 - hhh1 - 2 * v1) % q
    m0, m1 = v0 - x30, v1 - x31
    y30 = (r0 * m0 - 2 * r1 * m1 - (y0 * hhh0 - 2 * y1 * hhh1)) % q
    y31 = (r0 * m1 + r1 * m0 - (y0 * hhh1 + y1 * hhh0)) % q
    z30 = (z0 * h0 - 2 * z1 * h1) % q
    z31 = (z0 * h1 + z1 * h0) % q
    l0 = (z30 * ay0 - 2 * z31 * ay1 - (r0 * ax0 - 2 * r1 * ax1)) % q
    l6 = (z30 * ay1 + z31 * ay0 - (r0 * ax1 + r1 * ax0)) % q
    line = (l0, r0 * xp % q, -z30 * yp % q, l6, r1 * xp % q, -z31 * yp % q)
    return (x30, x31, y30, y31, z30, z31), line


def miller_loop(p: Sequence[int], q_point: Sequence[int]) -> tuple:
    """The Miller function of the R-ate pairing, before the final exponentiation."""
    xp, yp = p
    t = (*q_point, 1, 0)
    f = ONE
    first = True
    for bit in _LOOP_BITS:
        t, line = _double_step(t, xp, yp)
        if first:  # f = 1, so f^2 * line is the line itself
            f = mul_line(ONE, *line)
            first = False
        else:
            f = mul_line(sqr(f), *line)
        if bit == "1":
            t, line = _add_step(t, q_point, xp, yp)
            if line is not None:
                f = mul_line(f, *line)
    q1 = twist_frobenius(q_point)
    q2 = twist_frobenius(q1)
    t, line = _add_step(t, q1, xp, yp)
    if line is not None:
        f = mul_line(f, *line)
    _, line = _add_step(t, (q2[0], q2[1], (Q - q2[2]) % Q, (Q - q2[3]) % Q), xp, yp)
    if line is not None:
        f = mul_line(f, *line)
    return f


def pairing(p: Sequence[int] | None, q_point: Sequence[int] | None) -> tuple:
    """e(P, Q) for affine P in G1 and Q in G2; 1 if either is the identity (None)."""
    if p is None or q_point is None:
        return ONE
    return final_exponentiation(miller_loop(p, q_point))


__all__ = ["mul", "pairing", "twist_frobenius"]
