"""SM9 groups G1 = E(Fq), y^2 = x^3 + 5, and G2 on the twist E'(Fq2), y^2 = x^3 + 5u.

Points are plain tuples. Affine G1 is ``(x, y)`` and affine G2 is ``(x0, x1, y0, y1)``
with x = x0 + x1 u. Jacobian G1 is ``(X, Y, Z)`` and Jacobian G2 is
``(X0, X1, Y0, Y1, Z0, Z1)``; Z = 0 is the point at infinity.

Secret scalars go through :func:`mul_secret`: signed odd digits in 5-bit windows, a
table of 1P, 3P, ..., 31P packed into one integer and read in full for every digit,
and the sign applied with masks (the method of :mod:`smx._ec`). The doubling and
addition formulas keep their special-case branches, which a random scalar reaches
with negligible probability. CPython integers give no constant-time guarantee; see
:mod:`smx._ec`. :func:`mul_public` is variable time and only for public scalars.
"""

from __future__ import annotations

from collections.abc import Sequence
from operator import itemgetter

from . import _ec
from ._sm9_field import N, Q, recode, select, select_levels

B = 5
P1 = (
    0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD,
    0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616,
)
P2 = (
    0x3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B,
    0x85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141,
    0xA7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7,
    0x17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96,
)

G1_INFINITY = (1, 1, 0)
G2_INFINITY = (1, 0, 1, 0, 0, 0)
G1_BYTES = 65
G2_BYTES = 129

_WINDOW = 5
_WINDOW_COUNT = 52
_WINDOW_MASK = (1 << _WINDOW) - 1
_TABLE_SIZE = 1 << (_WINDOW - 1)
_INDEX_MASK = _TABLE_SIZE - 1
_PUBLIC_WINDOW = 5
_SPLIT_COUNT = 4
_SPLIT_BITS = 64
_SPLIT_MASK = (1 << _SPLIT_BITS) - 1


# ---------------------------------------------------------------- G1 formulas


def g1_on_curve(x: int, y: int) -> bool:
    return 0 <= x < Q and 0 <= y < Q and (y * y - x * x * x - B) % Q == 0


def g1_double(point: tuple) -> tuple:
    """Double a Jacobian point (a = 0), including the special cases."""
    x1, y1, z1 = point
    if z1 == 0 or y1 == 0:
        return G1_INFINITY
    q = Q
    a = x1 * x1 % q
    b = y1 * y1 % q
    c = b * b % q
    d = 4 * x1 * b % q
    e = 3 * a
    x3 = (e * e - 2 * d) % q
    return x3, (e * (d - x3) - 8 * c) % q, 2 * y1 * z1 % q


def g1_add_affine(point: tuple, other: Sequence[int]) -> tuple:
    """Add an affine point to a Jacobian point, including the special cases."""
    x1, y1, z1 = point
    x2, y2 = other
    if z1 == 0:
        return x2, y2, 1
    q = Q
    z1z1 = z1 * z1 % q
    h = (x2 * z1z1 - x1) % q
    r = (y2 * (z1 * z1z1 % q) - y1) % q
    if h == 0:
        return g1_double(point) if r == 0 else G1_INFINITY
    hh = h * h % q
    hhh = hh * h % q
    v = x1 * hh % q
    x3 = (r * r - hhh - 2 * v) % q
    return x3, (r * (v - x3) - y1 * hhh) % q, z1 * h % q


def g1_to_affine(point: tuple, blinded: bool = True) -> tuple | None:
    """Affine coordinates, or None for infinity; blind Z when it may be secret."""
    x, y, z = point
    if z == 0:
        return None
    q = Q
    z_inv = _ec.invert_blinded(z, q) if blinded else pow(z, -1, q)
    z_inv2 = z_inv * z_inv % q
    return x * z_inv2 % q, y * z_inv2 % q * z_inv % q


def g1_negate(point: Sequence[int]) -> tuple:
    return point[0], (Q - point[1]) % Q


# ---------------------------------------------------------------- G2 formulas


def g2_on_curve(x0: int, x1: int, y0: int, y1: int) -> bool:
    q = Q
    if not all(0 <= c < q for c in (x0, x1, y0, y1)):
        return False
    xx0, xx1 = x0 * x0 - 2 * x1 * x1, 2 * x0 * x1
    xxx0 = (xx0 * x0 - 2 * xx1 * x1) % q
    xxx1 = (xx0 * x1 + xx1 * x0) % q
    yy0, yy1 = (y0 * y0 - 2 * y1 * y1) % q, 2 * y0 * y1 % q
    return yy0 == xxx0 and yy1 == (xxx1 + B) % q


def g2_double(point: tuple) -> tuple:
    """Double a Jacobian twist point (a = 0), including the special cases."""
    x0, x1, y0, y1, z0, z1 = point
    if (z0 == 0 and z1 == 0) or (y0 == 0 and y1 == 0):
        return G2_INFINITY
    q = Q
    a0, a1 = (x0 * x0 - 2 * x1 * x1) % q, 2 * x0 * x1 % q
    b0, b1 = (y0 * y0 - 2 * y1 * y1) % q, 2 * y0 * y1 % q
    c0, c1 = (b0 * b0 - 2 * b1 * b1) % q, 2 * b0 * b1 % q
    d0, d1 = 4 * (x0 * b0 - 2 * x1 * b1) % q, 4 * (x0 * b1 + x1 * b0) % q
    e0, e1 = 3 * a0, 3 * a1
    x30 = (e0 * e0 - 2 * e1 * e1 - 2 * d0) % q
    x31 = (2 * e0 * e1 - 2 * d1) % q
    m0, m1 = d0 - x30, d1 - x31
    return (
        x30,
        x31,
        (e0 * m0 - 2 * e1 * m1 - 8 * c0) % q,
        (e0 * m1 + e1 * m0 - 8 * c1) % q,
        2 * (y0 * z0 - 2 * y1 * z1) % q,
        2 * (y0 * z1 + y1 * z0) % q,
    )


def g2_add_affine(point: tuple, other: Sequence[int]) -> tuple:
    """Add an affine twist point to a Jacobian one, including the special cases."""
    x0, x1, y0, y1, z0, z1 = point
    ax0, ax1, ay0, ay1 = other
    if z0 == 0 and z1 == 0:
        return ax0, ax1, ay0, ay1, 1, 0
    q = Q
    zz0, zz1 = (z0 * z0 - 2 * z1 * z1) % q, 2 * z0 * z1 % q
    zzz0, zzz1 = (zz0 * z0 - 2 * zz1 * z1) % q, (zz0 * z1 + zz1 * z0) % q
    h0 = (ax0 * zz0 - 2 * ax1 * zz1 - x0) % q
    h1 = (ax0 * zz1 + ax1 * zz0 - x1) % q
    r0 = (ay0 * zzz0 - 2 * ay1 * zzz1 - y0) % q
    r1 = (ay0 * zzz1 + ay1 * zzz0 - y1) % q
    if h0 == 0 and h1 == 0:
        if r0 == 0 and r1 == 0:
            return g2_double(point)
        return G2_INFINITY
    hh0, hh1 = (h0 * h0 - 2 * h1 * h1) % q, 2 * h0 * h1 % q
    hhh0, hhh1 = (hh0 * h0 - 2 * hh1 * h1) % q, (hh0 * h1 + hh1 * h0) % q
    v0, v1 = (x0 * hh0 - 2 * x1 * hh1) % q, (x0 * hh1 + x1 * hh0) % q
    x30 = (r0 * r0 - 2 * r1 * r1 - hhh0 - 2 * v0) % q
    x31 = (2 * r0 * r1 - hhh1 - 2 * v1) % q
    m0, m1 = v0 - x30, v1 - x31
    return (
        x30,
        x31,
        (r0 * m0 - 2 * r1 * m1 - (y0 * hhh0 - 2 * y1 * hhh1)) % q,
        (r0 * m1 + r1 * m0 - (y0 * hhh1 + y1 * hhh0)) % q,
        (z0 * h0 - 2 * z1 * h1) % q,
        (z0 * h1 + z1 * h0) % q,
    )


def g2_to_affine(point: tuple, blinded: bool = True) -> tuple | None:
    """Affine coordinates, or None for infinity; blind Z when it may be secret."""
    x0, x1, y0, y1, z0, z1 = point
    if z0 == 0 and z1 == 0:
        return None
    q = Q
    norm = (z0 * z0 + 2 * z1 * z1) % q
    norm_inv = _ec.invert_blinded(norm, q) if blinded else pow(norm, -1, q)
    i0, i1 = z0 * norm_inv % q, -z1 * norm_inv % q  # 1/Z
    s0, s1 = (i0 * i0 - 2 * i1 * i1) % q, 2 * i0 * i1 % q  # 1/Z^2
    c0, c1 = (s0 * i0 - 2 * s1 * i1) % q, (s0 * i1 + s1 * i0) % q  # 1/Z^3
    return (
        (x0 * s0 - 2 * x1 * s1) % q,
        (x0 * s1 + x1 * s0) % q,
        (y0 * c0 - 2 * y1 * c1) % q,
        (y0 * c1 + y1 * c0) % q,
    )


def g2_negate(point: Sequence[int]) -> tuple:
    return point[0], point[1], (Q - point[2]) % Q, (Q - point[3]) % Q


def _jacobian(affine: Sequence[int]) -> tuple:
    return (*affine, 1) if len(affine) == 2 else (*affine, 1, 0)


class _Group:
    """The formulas and the table layout of one group, for the shared drivers."""

    __slots__ = (
        "add",
        "coordinates",
        "double",
        "infinity",
        "lane_bits",
        "levels",
        "neg_masks",
        "negate",
        "q_slots",
        "sentinel",
        "to_affine",
        "y_slots",
    )

    def __init__(self, coordinates: int, double, add, to_affine, negate, infinity):
        self.coordinates = coordinates
        self.double = double
        self.add = add
        self.to_affine = to_affine
        self.negate = negate
        self.infinity = infinity
        self.lane_bits = 256 * coordinates + 1
        self.sentinel = 1 << (256 * coordinates)
        self.levels = select_levels(self.lane_bits)
        half = coordinates // 2  # the y coordinates are the upper half of the slots
        slot = (1 << 256) - 1
        self.y_slots = sum(slot << (256 * i) for i in range(half, coordinates))
        self.q_slots = sum(Q << (256 * i) for i in range(half, coordinates))
        # Keep or drop a value below the sentinel; both masks have the same size.
        self.neg_masks = (self.sentinel, (self.sentinel << 1) - 1)


G1 = _Group(2, g1_double, g1_add_affine, g1_to_affine, g1_negate, G1_INFINITY)
G2 = _Group(4, g2_double, g2_add_affine, g2_to_affine, g2_negate, G2_INFINITY)


def _is_infinity(point: tuple) -> bool:
    return not any(point[-2:]) if len(point) == 6 else point[2] == 0


def _odd_multiples(group: _Group, base: Sequence[int], blinded: bool) -> list[tuple]:
    """Affine 1P, 3P, ..., 31P for a point P of order n."""
    twice = group.to_affine(group.double(_jacobian(base)), blinded)
    if twice is None:
        raise ValueError("point is not in the group of order n")
    current = _jacobian(base)
    multiples = [tuple(base)]
    for _ in range(_TABLE_SIZE - 1):
        current = group.add(current, twice)
        affine = group.to_affine(current, blinded)
        if affine is None:
            raise ValueError("point is not in the group of order n")
        multiples.append(affine)
    return multiples


def secret_table(group: _Group, base: Sequence[int]) -> int:
    """Pack 1P, 3P, ..., 31P, one lane of ``1 || y || x`` coordinates each."""
    packed = 0
    for i, point in enumerate(_odd_multiples(group, base, True)):
        lane = group.sentinel
        for slot, coordinate in enumerate(point):
            lane |= coordinate << (256 * slot)
        packed |= lane << (i * group.lane_bits)
    return packed


def _signed_lookup(group: _Group, table: int, digit: int) -> tuple:
    positive = digit >> (_WINDOW - 1)
    lane = select(table, (digit ^ (positive - 1)) & _INDEX_MASK, group.levels)
    y = lane & group.y_slots
    negated = group.q_slots - y  # Q - y in each y slot; no borrow crosses a slot
    masks = group.neg_masks
    lane = (
        (lane & ~group.y_slots)
        | (y & masks[positive])
        | (negated & masks[1 - positive])
    )
    data = (lane ^ group.sentinel).to_bytes(32 * group.coordinates, "little")
    return tuple(
        int.from_bytes(data[32 * i : 32 * i + 32], "little")
        for i in range(group.coordinates)
    )


def mul_secret(group: _Group, base: Sequence[int], k: int, table: int = 0) -> tuple:
    """[k]P for a secret k in [1, n-1] and P of order n; returns a Jacobian point.

    Every window costs five doublings and one addition, with the whole table read.
    """
    if not table:
        table = secret_table(group, base)
    double, add = group.double, group.add
    digits = recode(k, N)
    top = _WINDOW * (_WINDOW_COUNT - 1)
    result = _jacobian(_signed_lookup(group, table, digits >> top))
    for shift in range(top - _WINDOW, -1, -_WINDOW):
        result = double(double(double(double(double(result)))))
        result = add(
            result, _signed_lookup(group, table, digits >> shift & _WINDOW_MASK)
        )
    return result


# ---------------------------------------------------------------- public scalars


def _wnaf(k: int, window: int) -> list[tuple[int, int]]:
    """Non-zero width-``window`` NAF digits of k as (position, digit)."""
    size = 1 << window
    half = size >> 1
    mask = size - 1
    digits = []
    position = 0
    while k:
        zeros = (k & -k).bit_length() - 1
        position += zeros
        k >>= zeros
        digit = k & mask
        if digit >= half:
            digit -= size
        digits.append((position, digit))
        k = (k - digit) >> window
        position += window
    return digits


def _lookup(group: _Group, base: Sequence[int], window: int) -> list | None:
    """Index by a signed odd digit; negative digits use negative list indices.

    Returns None if a multiple is the point at infinity (P of small order).
    """
    count = 1 << (window - 1)
    twice = group.to_affine(group.double(_jacobian(base)), False)
    if twice is None:
        return None
    current = _jacobian(base)
    affine = [tuple(base)]
    for _ in range(count - 1):
        current = group.add(current, twice)
        point = group.to_affine(current, False)
        if point is None:
            return None
        affine.append(point)
    lookup: list = [None] * (2 * count + 1)
    for i, point in enumerate(affine):
        lookup[2 * i + 1] = point
        lookup[-2 * i - 1] = group.negate(point)
    return lookup


def _run_additions(group: _Group, additions: list) -> tuple:
    """Sum [2**position]P terms with one shared doubling chain."""
    result = group.infinity
    if not additions:
        return result
    double, add = group.double, group.add
    additions.sort(key=itemgetter(0), reverse=True)
    current = additions[0][0]
    for position, point in additions:
        for _ in range(current - position):
            result = double(result)
        current = position
        result = add(result, point)
    for _ in range(current):
        result = double(result)
    return result


def _double_and_add(group: _Group, base: Sequence[int], k: int) -> tuple:
    result = group.infinity
    for i in range(k.bit_length() - 1, -1, -1):
        result = group.double(result)
        if (k >> i) & 1:
            result = group.add(result, base)
    return result


def mul_public(group: _Group, base: Sequence[int], k: int) -> tuple:
    """[k]P for a public k >= 0 and any on-curve P. Variable time."""
    if k == 0:
        return group.infinity
    lookup = _lookup(group, base, _PUBLIC_WINDOW)
    if lookup is None:
        return _double_and_add(group, base, k)
    return _run_additions(
        group,
        [(position, lookup[digit]) for position, digit in _wnaf(k, _PUBLIC_WINDOW)],
    )


class FixedBase:
    """Lookups for P, [2**64]P, [2**128]P, [2**192]P: 64 doublings per public scalar.

    Only for the generators P1 and P2, whose multiples are never the identity.
    """

    __slots__ = ("group", "lookups", "window")

    def __init__(self, group: _Group, base: Sequence[int], window: int = 6) -> None:
        self.group = group
        self.window = window
        self.lookups = []
        point = tuple(base)
        for _ in range(_SPLIT_COUNT):
            self.lookups.append(_lookup(group, point, window))
            jacobian = _jacobian(point)
            for _bit in range(_SPLIT_BITS):
                jacobian = group.double(jacobian)
            point = group.to_affine(jacobian, False)

    def multiply(self, k: int) -> tuple:
        """[k]P for a public k in [0, 2**256). Variable time."""
        additions = []
        for lookup in self.lookups:
            for position, digit in _wnaf(k & _SPLIT_MASK, self.window):
                additions.append((position, lookup[digit]))
            k >>= _SPLIT_BITS
        return _run_additions(self.group, additions)


def in_g2_subgroup(point: Sequence[int]) -> bool:
    """[n]Q == O for an on-curve twist point. Variable time; for public checks."""
    return _is_infinity(mul_public(G2, point, N))


# ---------------------------------------------------------------- encodings


def g1_to_bytes(point: Sequence[int]) -> bytes:
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def g1_xy(point: Sequence[int]) -> bytes:
    return point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def g2_to_bytes(point: Sequence[int]) -> bytes:
    x0, x1, y0, y1 = point
    return b"\x04" + b"".join(v.to_bytes(32, "big") for v in (x1, x0, y1, y0))


def g1_from_bytes(data: bytes) -> tuple | None:
    """Decode exactly 04 || x || y of an on-curve point, else None."""
    if len(data) != G1_BYTES or data[0] != 4:
        return None
    x = int.from_bytes(data[1:33], "big")
    y = int.from_bytes(data[33:], "big")
    return (x, y) if g1_on_curve(x, y) else None


def g2_from_bytes(data: bytes) -> tuple | None:
    """Decode 04 || x1 || x0 || y1 || y0 of a point of G2 (subgroup checked), else None."""
    if len(data) != G2_BYTES or data[0] != 4:
        return None
    x1, x0, y1, y0 = (int.from_bytes(data[i : i + 32], "big") for i in (1, 33, 65, 97))
    if not g2_on_curve(x0, x1, y0, y1):
        return None
    point = (x0, x1, y0, y1)
    return point if in_g2_subgroup(point) else None
