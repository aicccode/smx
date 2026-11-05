"""SM2 field and group internals: Jacobian formulas, tables, scalar multiplication.

Plain ``%`` is the fastest reduction available here: in CPython it costs 170 ns on
a 512-bit product, while a Solinas reduction written in Python costs 660 ns. For
the same reason nothing below tries to replace Python's integers with limbs.

Timing, stated plainly: **CPython integers give no constant-time guarantee.**
Multiplication, ``%``, ``&`` and object allocation all take time that can depend
on the values. What this module does for secret scalars is remove what it can
control: no branch and no table index depends on the scalar (apart from a branch
that a random scalar reaches with negligible probability), the whole table is read
for each digit, and Z is blinded before the variable-time inversion. That raises
the bar and does not make the code constant-time. Do not use this library where an
attacker can take precise timing or cache measurements of the process.

``mul_public`` and ``mul_shamir`` are variable time and are only for public scalars.
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from functools import lru_cache
from operator import itemgetter

P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

Jacobian = tuple[int, int, int]
Affine = tuple[int, int]
INFINITY: Jacobian = (1, 1, 0)

_COORD_MASK = (1 << 256) - 1

# Signed odd-digit recoding with 5-bit windows, shared by both secret-scalar paths.
_WINDOW = 5
_WINDOW_COUNT = 52  # 52 * 5 = 260 bits, enough for k + n < 2**257
_WINDOW_MASK = (1 << _WINDOW) - 1
_TABLE_SIZE = 1 << (_WINDOW - 1)  # the odd multiples 1P, 3P, ..., 31P
_INDEX_MASK = _TABLE_SIZE - 1
_RECODE_OFFSET = (1 << (_WINDOW * _WINDOW_COUNT)) - 1

# A table is one integer of 16 lanes, and a lane is ``1 || x || y``. The set top bit
# keeps every intermediate the same size, so CPython's shortcuts for small or zero
# operands never see a selected or unselected value.
_LANE_BITS = 513
_LANE_SENTINEL = 1 << 512
_SELECT_LEVELS = tuple(
    (
        level,
        _LANE_BITS << level,
        (1 << ((_LANE_BITS << level) - 1), (1 << (_LANE_BITS << level)) - 1),
    )
    for level in range(_WINDOW - 2, -1, -1)
)

_G_WNAF_WINDOW = 8
_P_WNAF_WINDOW = 6  # uses the same 1P..31P as the secret-scalar table
_SPLIT_COUNT = 4
_SPLIT_BITS = 64
_SPLIT_MASK = (1 << _SPLIT_BITS) - 1


def invert_blinded(value: int, modulus: int) -> int:
    """Invert a secret value modulo a prime without showing it to ``pow``.

    ``pow(x, -1, m)`` runs a variable-time Euclidean algorithm, so it only ever
    sees ``value * r``, where r is a fresh uniform blinding factor.
    """
    blind = secrets.randbelow(modulus - 1) + 1
    return blind * pow(value * blind % modulus, -1, modulus) % modulus


def double(point: Jacobian) -> Jacobian:
    """Double a Jacobian point (a = -3 formulas), including the special cases."""
    x1, y1, z1 = point
    if z1 == 0 or y1 == 0:
        return INFINITY
    p = P
    delta = z1 * z1 % p
    gamma = y1 * y1 % p
    beta = x1 * gamma % p
    alpha = 3 * (x1 - delta) * (x1 + delta) % p
    x3 = (alpha * alpha - 8 * beta) % p
    y3 = (alpha * (4 * beta - x3) - 8 * gamma * gamma) % p
    return x3, y3, 2 * y1 * z1 % p


def add_affine(point: Jacobian, x2: int, y2: int) -> Jacobian:
    """Add an affine point to a Jacobian point, including the special cases."""
    x1, y1, z1 = point
    if z1 == 0:
        return x2, y2, 1
    p = P
    z1z1 = z1 * z1 % p
    h = (x2 * z1z1 - x1) % p
    r = (y2 * (z1 * z1z1 % p) - y1) % p
    if h == 0:
        return double(point) if r == 0 else INFINITY
    hh = h * h % p
    hhh = hh * h % p
    x1hh = x1 * hh % p
    x3 = (r * r - hhh - 2 * x1hh) % p
    return x3, (r * (x1hh - x3) - y1 * hhh) % p, z1 * h % p


def to_affine_public(point: Jacobian) -> Affine | None:
    """Convert to affine with an unblinded inversion; None for infinity."""
    x, y, z = point
    if z == 0:
        return None
    p = P
    z_inv = pow(z, -1, p)
    z_inv2 = z_inv * z_inv % p
    return x * z_inv2 % p, y * z_inv2 % p * z_inv % p


def to_affine_blinded(point: Jacobian) -> Affine | None:
    """Convert to affine when Z may depend on a secret; None for infinity."""
    x, y, z = point
    if z == 0:
        return None
    p = P
    z_inv = invert_blinded(z, p)
    z_inv2 = z_inv * z_inv % p
    return x * z_inv2 % p, y * z_inv2 % p * z_inv % p


def batch_to_affine(points: Sequence[Jacobian]) -> list[Affine]:
    """Convert finite points of public value using one inversion (Montgomery's trick)."""
    p = P
    products = []
    running = 1
    for _, _, z in points:
        running = running * z % p
        products.append(running)
    inverse = pow(running, -1, p)
    result: list[Affine] = [(0, 0)] * len(points)
    for i in range(len(points) - 1, -1, -1):
        x, y, z = points[i]
        z_inv = inverse * products[i - 1] % p if i else inverse
        inverse = inverse * z % p
        z_inv2 = z_inv * z_inv % p
        result[i] = (x * z_inv2 % p, y * z_inv2 % p * z_inv % p)
    return result


def _odd_multiples(x: int, y: int, count: int) -> list[Jacobian]:
    """Return 1P, 3P, ..., (2*count - 1)P as Jacobian points."""
    twice = to_affine_public(double((x, y, 1)))
    assert twice is not None  # P has odd prime order
    x2, y2 = twice
    current: Jacobian = (x, y, 1)
    multiples = [current]
    for _ in range(count - 1):
        current = add_affine(current, x2, y2)
        multiples.append(current)
    return multiples


def _pack_table(entries: Sequence[Affine]) -> int:
    packed = 0
    for i, (x, y) in enumerate(entries):
        packed |= (_LANE_SENTINEL | x << 256 | y) << (i * _LANE_BITS)
    return packed


def _select(table: int, index: int) -> int:
    """Return lane ``index``, reading every lane and every mask for any index.

    Each level halves the table with one bit of the index. Both masks of a level
    are always used, the only difference being which half each one is applied to.
    """
    for level, half_bits, masks in _SELECT_LEVELS:
        bit = index >> level & 1
        table = (table & masks[1 - bit]) | (table >> half_bits & masks[bit])
    return table


def _recode(k: int) -> int:
    """Return A with k' = 2A - (2**260 - 1), where k' is k or k + n, whichever is odd.

    Reading A in base 32 gives digits a_i for which d_i = 2*a_i - 31 is odd and
    non-zero, and k' = sum(d_i * 32**i). No digit needs a carry or a branch.
    """
    return (k + N * (~k & 1) + _RECODE_OFFSET) >> 1


def mul_double_and_add(x: int, y: int, k: int) -> Jacobian:
    """Compute [k]P for any point and any k > 0. Variable time, handles every case.

    Off-curve input can only reach this function through ``ECPoint.multiply``, and
    every sm2_* function rejects off-curve points first. It is also the fallback
    for the exceptional scalars of the two fixed-window functions below.
    """
    result = INFINITY
    for i in range(k.bit_length() - 1, -1, -1):
        result = double(result)
        if (k >> i) & 1:
            result = add_affine(result, x, y)
    return result


# Fixed-base multiplication -------------------------------------------------


def _build_generator_rows() -> tuple[int, ...]:
    rows = []
    x, y = GX, GY
    for _ in range(_WINDOW_COUNT):
        multiples = _odd_multiples(x, y, _TABLE_SIZE)
        # The last odd multiple plus the base is the base of the next row.
        next_base = add_affine(multiples[-1], x, y)
        affine = batch_to_affine(multiples + [next_base])
        x, y = affine.pop()
        rows.append(_pack_table(affine))
    return tuple(rows)


_generator_rows: tuple[int, ...] | None = None


def mul_generator(k: int) -> Jacobian:
    """Compute [k]G for a secret k in [1, n-1], with a comb of 52 x 16 points.

    The rows are built on first use (a few milliseconds). Each row contributes
    exactly one mixed addition. Partial sums stay below the next row's weight, so
    the additions can only meet the same point in the top row, with k = 2**256 - n.
    A random scalar has a negligible chance of being that value, and that path
    still returns the correct result.
    """
    global _generator_rows
    rows = _generator_rows
    if rows is None:
        rows = _generator_rows = _build_generator_rows()

    p = P
    coord_mask = _COORD_MASK
    sentinel = 1 << 256
    index_mask = _INDEX_MASK
    window = _WINDOW
    window_mask = _WINDOW_MASK
    top_bit = window - 1
    digits = _recode(k)
    x1 = y1 = 0
    z1 = 0
    for table in rows:
        digit = digits & window_mask
        digits >>= window
        positive = digit >> top_bit
        lane = _select(table, (digit ^ (positive - 1)) & index_mask)
        x2 = lane >> 256 ^ sentinel
        y2 = (lane & coord_mask) * (2 * positive - 1)
        if z1 == 0:
            x1, y1, z1 = x2, y2 % p, 1
            continue
        z1z1 = z1 * z1 % p
        h = (x2 * z1z1 - x1) % p
        if h == 0:
            return mul_double_and_add(GX, GY, k)
        r = (y2 * (z1 * z1z1 % p) - y1) % p
        hh = h * h % p
        hhh = hh * h % p
        x1hh = x1 * hh % p
        x3 = (r * r - hhh - 2 * x1hh) % p
        y1 = (r * (x1hh - x3) - y1 * hhh) % p
        x1 = x3
        z1 = z1 * h % p
    return x1, y1, z1


# Variable-base multiplication ----------------------------------------------


def _signed_lookup(affine: Sequence[Affine]) -> list[Affine | None]:
    """Index by a signed odd wNAF digit; negative digits use Python's negative indices.

    The odd length sends +d to odd positions and -d to even ones, so they never meet.
    """
    lookup: list[Affine | None] = [None] * (2 * len(affine) + 1)
    for i, (x, y) in enumerate(affine):
        lookup[2 * i + 1] = (x, y)
        lookup[-2 * i - 1] = (x, P - y)
    return lookup


class _KeyTables:
    """Tables kept for one long-lived public key."""

    __slots__ = ("lookup", "packed", "split_lookups", "verify_count")

    def __init__(self, x: int, y: int) -> None:
        affine = batch_to_affine(_odd_multiples(x, y, _TABLE_SIZE))
        self.packed = _pack_table(affine)
        self.lookup = _signed_lookup(affine)
        self.split_lookups: list[list[Affine | None]] | None = None
        self.verify_count = 0


@lru_cache(maxsize=32)
def cached_key_tables(x: int, y: int) -> _KeyTables:
    """Return the tables of a public key. Never pass a secret point here."""
    return _KeyTables(x, y)


def mul_point(x: int, y: int, k: int) -> Jacobian:
    """Compute [k]P for an on-curve P and a secret k in [1, n-1]."""
    table = _pack_table(batch_to_affine(_odd_multiples(x, y, _TABLE_SIZE)))
    return mul_point_with_table(x, y, k, table)


def mul_point_with_table(x: int, y: int, k: int, table: int) -> Jacobian:
    """Compute [k]P with a fixed window and a table of 1P, 3P, ..., 31P.

    Every window costs five doublings and one mixed addition. The additions can only
    meet the same point in the last window, with k = n - 6. A random scalar has a
    negligible chance of being that value, and that path still returns the correct
    result.
    """
    p = P
    sentinel = 1 << 256
    coord_mask = _COORD_MASK
    index_mask = _INDEX_MASK
    window_mask = _WINDOW_MASK
    top_bit = _WINDOW - 1
    digits = _recode(k)
    top_shift = _WINDOW * (_WINDOW_COUNT - 1)

    digit = digits >> top_shift
    positive = digit >> top_bit
    lane = _select(table, (digit ^ (positive - 1)) & index_mask)
    x1 = lane >> 256 ^ sentinel
    y1 = (lane & coord_mask) * (2 * positive - 1) % p
    z1 = 1

    for shift in range(top_shift - _WINDOW, -1, -_WINDOW):
        for _ in (0, 1, 2, 3, 4):
            delta = z1 * z1 % p
            gamma = y1 * y1 % p
            beta = x1 * gamma % p
            alpha = 3 * (x1 - delta) * (x1 + delta) % p
            z1 = 2 * y1 * z1 % p
            x1 = (alpha * alpha - 8 * beta) % p
            y1 = (alpha * (4 * beta - x1) - 8 * gamma * gamma) % p

        digit = digits >> shift & window_mask
        positive = digit >> top_bit
        lane = _select(table, (digit ^ (positive - 1)) & index_mask)
        x2 = lane >> 256 ^ sentinel
        y2 = (lane & coord_mask) * (2 * positive - 1)

        z1z1 = z1 * z1 % p
        h = (x2 * z1z1 - x1) % p
        if h == 0:
            return mul_double_and_add(x, y, k)
        r = (y2 * (z1 * z1z1 % p) - y1) % p
        hh = h * h % p
        hhh = hh * h % p
        x1hh = x1 * hh % p
        x3 = (r * r - hhh - 2 * x1hh) % p
        y1 = (r * (x1hh - x3) - y1 * hhh) % p
        x1 = x3
        z1 = z1 * h % p
    return x1, y1, z1


# Public-scalar multiplication (variable time) --------------------------------


def _wnaf(k: int, window: int) -> list[tuple[int, int]]:
    """Return the non-zero width-``window`` NAF digits of k as (position, digit)."""
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


def _run_additions(additions: list[tuple[int, Affine]]) -> Jacobian:
    """Evaluate a sum of [2**position]Q terms with one shared doubling chain."""
    p = P
    additions.sort(key=itemgetter(0), reverse=True)
    x1, y1, z1 = INFINITY
    current = additions[0][0]
    additions.append((0, (0, 0)))  # runs the final doublings; never added
    last = len(additions) - 1
    for number, (position, (x2, y2)) in enumerate(additions):
        for _ in range(current - position):
            if z1:
                delta = z1 * z1 % p
                gamma = y1 * y1 % p
                beta = x1 * gamma % p
                alpha = 3 * (x1 - delta) * (x1 + delta) % p
                z1 = 2 * y1 * z1 % p
                x1 = (alpha * alpha - 8 * beta) % p
                y1 = (alpha * (4 * beta - x1) - 8 * gamma * gamma) % p
        current = position
        if number != last:
            x1, y1, z1 = add_affine((x1, y1, z1), x2, y2)
    return x1, y1, z1


def _lookups_for_split(x: int, y: int, window: int) -> list[list[Affine | None]]:
    """Return lookups for P, [2**64]P, [2**128]P and [2**192]P."""
    count = 1 << (window - 1)
    lookups = []
    for _ in range(_SPLIT_COUNT):
        lookups.append(_signed_lookup(batch_to_affine(_odd_multiples(x, y, count))))
        point: Jacobian = (x, y, 1)
        for _bit in range(_SPLIT_BITS):
            point = double(point)
        affine = to_affine_public(point)
        assert affine is not None  # P has odd prime order
        x, y = affine
    return lookups


def _split_terms(
    k: int, window: int, lookups: list[list[Affine | None]]
) -> list[tuple[int, Affine]]:
    terms = []
    for lookup in lookups:
        for position, digit in _wnaf(k & _SPLIT_MASK, window):
            terms.append((position, lookup[digit]))
        k >>= _SPLIT_BITS
    return terms


_generator_lookups: list[list[Affine | None]] = []
_generator_split_lookups: list[list[Affine | None]] = []


def _get_generator_lookups() -> list[list[Affine | None]]:
    global _generator_lookups
    lookups = _generator_lookups
    if not lookups:
        count = 1 << (_G_WNAF_WINDOW - 1)
        affine = batch_to_affine(_odd_multiples(GX, GY, count))
        lookups = _generator_lookups = [_signed_lookup(affine)]
    return lookups


def _get_generator_split_lookups() -> list[list[Affine | None]]:
    global _generator_split_lookups
    lookups = _generator_split_lookups
    if not lookups:
        lookups = _lookups_for_split(GX, GY, _G_WNAF_WINDOW)
        _generator_split_lookups = lookups
    return lookups


def mul_public(x: int, y: int, k: int) -> Jacobian:
    """Compute [k]P for an on-curve P and a public k > 0. Variable time."""
    lookup = _signed_lookup(batch_to_affine(_odd_multiples(x, y, _TABLE_SIZE)))
    return _run_additions(
        [(position, lookup[digit]) for position, digit in _wnaf(k, _P_WNAF_WINDOW)]
    )


def mul_shamir(s: int, t: int, x: int, y: int) -> Jacobian:
    """Compute [s]G + [t]P for public s, t in [1, n-1] and a public key P. Variable time.

    From the second verification with a key on, the scalars are split into four
    64-bit parts over precomputed multiples of G and P. That needs 64 doublings
    instead of 256. A key that is used once never pays for its split tables.
    """
    tables = cached_key_tables(x, y)
    if tables.verify_count == 0:
        tables.verify_count = 1
        g_lookup = _get_generator_lookups()[0]
        additions = [
            (position, g_lookup[digit]) for position, digit in _wnaf(s, _G_WNAF_WINDOW)
        ]
        lookup = tables.lookup
        additions += [
            (position, lookup[digit]) for position, digit in _wnaf(t, _P_WNAF_WINDOW)
        ]
        return _run_additions(additions)

    split_lookups = tables.split_lookups
    if split_lookups is None:
        split_lookups = _lookups_for_split(x, y, _P_WNAF_WINDOW)
        tables.split_lookups = split_lookups
    additions = _split_terms(s, _G_WNAF_WINDOW, _get_generator_split_lookups())
    additions += _split_terms(t, _P_WNAF_WINDOW, split_lookups)
    return _run_additions(additions)


def clear_caches() -> None:
    """Forget per-key tables. The generator tables stay, as they are not per key."""
    cached_key_tables.cache_clear()
