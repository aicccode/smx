//! Scalar multiplication strategies.
//!
//! - `mul_base`: secret k, fixed-base signed windows, no doublings.
//! - `mul_ct`: secret k, variable base, fixed signed windows.
//! - `mul_public`, `mul_base_and_public`: public scalars only, wNAF with Strauss-Shamir.
//!
//! The constant-time paths scan each whole table with masks. For a point of prime order n and
//! k < n, the incomplete addition can only meet its doubling case at the last window: before
//! window j the accumulator holds S * 2^(5j) * P with S a multiple of 32, and for j > 0 we have
//! |S| + 16 < n, so S = +-d (mod n) would force S = 0, i.e. an infinite accumulator, which is
//! selected away. Other inputs (off-curve points, for which the order is unknown) get the full
//! case handling in every window.

use super::curve::{Affine, Jacobian, normalize_batch};
use super::field::{Limbs, ct_barrier, fe_add, fe_mul, fe_neg, fe_sqr, fe_sub, select};
use super::order::reduce_scalar;
use super::point::SM2_B;
use super::precomp::{COMB_ENTRIES, COMB_WIDTH, COMB_WINDOWS, G_COMB, G_ODD, G_ODD_WIDTH};

/// Width of the windows for variable bases.
const WIDTH: usize = 5;
const WINDOWS: usize = 256 / WIDTH + 1;
const ENTRIES: usize = 1 << (WIDTH - 1);

/// wNAF width for variable bases with public scalars.
const VARIABLE_ODD_WIDTH: usize = 5;
const VARIABLE_ODD_ENTRIES: usize = 1 << (VARIABLE_ODD_WIDTH - 2);

/// Bits `[start, start + count)` of k, count <= 57; bits beyond 255 read as zero.
#[inline(always)]
fn bits(k: &Limbs, start: usize, count: u32) -> u64 {
    let limb = start / 64;
    if limb >= 4 {
        return 0;
    }
    let shift = start % 64;
    let mut value = k[limb] >> shift;
    if shift != 0 && limb + 1 < 4 {
        value |= k[limb + 1] << (64 - shift);
    }
    value & ((1u64 << count) - 1)
}

/// All ones when `a == b`.
#[inline(always)]
fn eq_mask(a: u64, b: u64) -> u64 {
    let d = a ^ b;
    ct_barrier(((d | d.wrapping_neg()) >> 63).wrapping_sub(1))
}

/// Booth digit of window `index` as (magnitude, negative mask), magnitude <= 2^(width-1).
#[inline(always)]
fn booth_digit(k: &Limbs, index: usize, width: u32) -> (u64, u64) {
    let position = index * width as usize;
    let raw = if position == 0 {
        (bits(k, 0, width) << 1) & ((1 << (width + 1)) - 1)
    } else {
        bits(k, position - 1, width + 1)
    };
    let negative = ct_barrier((raw >> width).wrapping_neg());
    let complement = ((1u64 << (width + 1)) - 1) - raw;
    let value = (complement & negative) | (raw & !negative);
    ((value >> 1) + (value & 1), negative)
}

/// Constant-time table scan; magnitude 0 returns zeros (recognized by the caller's mask).
#[inline]
fn lookup_affine(table: &[Affine; COMB_ENTRIES], magnitude: u64) -> Affine {
    let mut out = Affine::ZERO;
    for (i, entry) in table.iter().enumerate() {
        let mask = eq_mask(i as u64 + 1, magnitude);
        for l in 0..4 {
            out.x[l] |= entry.x[l] & mask;
            out.y[l] |= entry.y[l] & mask;
        }
    }
    out
}

/// Constant-time table scan; magnitude 0 returns Z = 0, which is the infinity representation.
#[inline]
fn lookup_jacobian(table: &[Jacobian; ENTRIES], magnitude: u64) -> Jacobian {
    let mut out = Jacobian {
        x: [0; 4],
        y: [0; 4],
        z: [0; 4],
    };
    for (i, entry) in table.iter().enumerate() {
        let mask = eq_mask(i as u64 + 1, magnitude);
        for l in 0..4 {
            out.x[l] |= entry.x[l] & mask;
            out.y[l] |= entry.y[l] & mask;
            out.z[l] |= entry.z[l] & mask;
        }
    }
    out
}

/// [k]G, constant time in k, for any 256-bit k.
pub(crate) fn mul_base(k: &Limbs) -> Jacobian {
    let k = reduce_scalar(k);
    let mut acc = Jacobian::INFINITY;
    for index in (0..COMB_WINDOWS).rev() {
        let (magnitude, negative) = booth_digit(&k, index, COMB_WIDTH as u32);
        let mut entry = lookup_affine(&G_COMB[index], magnitude);
        entry.y = select(negative, &fe_neg(&entry.y), &entry.y);
        acc = acc.add_mixed_ct(&entry, eq_mask(magnitude, 0), index == 0);
    }
    acc
}

/// True when (x, y) satisfies the curve equation.
pub(crate) fn is_on_curve(point: &Affine) -> bool {
    // x^3 - 3x + b = x (x^2 - 3) + b
    let x2_minus_3 = fe_sub(&fe_sqr(&point.x), &[3, 0, 0, 0]);
    let rhs = fe_add(&fe_mul(&x2_minus_3, &point.x), &SM2_B.value.limbs);
    fe_sqr(&point.y) == rhs
}

/// [k]P, constant time in k, for any 256-bit k and any finite (P is public) point.
///
/// On the curve, k is first reduced modulo the group order. Off the curve the group order is
/// unknown, so the exact integer k is used and every addition handles all cases.
pub(crate) fn mul_ct(point: &Affine, k: &Limbs) -> Jacobian {
    let on_curve = is_on_curve(point);
    let scalar = if on_curve { reduce_scalar(k) } else { *k };

    // The table only depends on the public point. The variable-time addition also copes with
    // the low-order points that can occur off the curve.
    let mut table = [point.to_jacobian(); ENTRIES];
    for i in 1..ENTRIES {
        table[i] = if i % 2 == 1 {
            table[i / 2].double()
        } else {
            table[i - 1].add_mixed_vartime(point)
        };
    }

    let mut acc = Jacobian::INFINITY;
    for index in (0..WINDOWS).rev() {
        if index != WINDOWS - 1 {
            for _ in 0..WIDTH {
                acc = acc.double();
            }
        }
        let (magnitude, negative) = booth_digit(&scalar, index, WIDTH as u32);
        let mut entry = lookup_jacobian(&table, magnitude);
        entry.y = select(negative, &fe_neg(&entry.y), &entry.y);
        acc = acc.add_ct(&entry, !on_curve || index == 0);
    }
    acc
}

/// wNAF digits of k, least significant first; returns the digits and how many are in use.
fn wnaf(k: &Limbs, width: usize) -> ([i16; 257], usize) {
    let mut digits = [0i16; 257];
    let mut carry = 0u64;
    let mut position = 0;
    let mut used = 0;
    while position < 257 {
        if bits(k, position, 1) == carry {
            position += 1;
            continue;
        }
        let word = bits(k, position, width as u32) + carry;
        carry = word >> (width - 1);
        let digit = word as i64 - ((carry << width) as i64);
        digits[position] = digit as i16;
        position += width;
        used = position.min(257);
    }
    (digits, used)
}

/// Odd multiples (1, 3, 5, ...) of a public point of unknown order, as affine points.
fn odd_multiples(point: &Affine) -> [Affine; VARIABLE_ODD_ENTRIES] {
    let base = point.to_jacobian();
    let twice = base.double();
    let mut jacobian = [base; VARIABLE_ODD_ENTRIES];
    for i in 1..VARIABLE_ODD_ENTRIES {
        jacobian[i] = jacobian[i - 1].add_vartime(&twice);
    }
    normalize_batch(&jacobian)
}

#[inline(always)]
fn add_wnaf_digit(acc: &Jacobian, digit: i16, table: &[Affine]) -> Jacobian {
    if digit > 0 {
        acc.add_mixed_vartime(&table[(digit as usize) / 2])
    } else if digit < 0 {
        acc.add_mixed_vartime(&table[(digit.unsigned_abs() as usize) / 2].negated())
    } else {
        *acc
    }
}

/// [s]G + [t]P with public s and t, in variable time, by Strauss-Shamir. `point` must be on the
/// curve (then all its odd multiples are finite and normalization is safe).
pub(crate) fn mul_base_and_public(s: &Limbs, t: &Limbs, point: Option<&Affine>) -> Jacobian {
    let (s_digits, s_used) = wnaf(s, G_ODD_WIDTH);
    let mut used = s_used;
    let mut t_digits = [0i16; 257];
    let mut table = [Affine::ZERO; VARIABLE_ODD_ENTRIES];
    if let Some(p) = point {
        let (digits, t_used) = wnaf(t, VARIABLE_ODD_WIDTH);
        t_digits = digits;
        used = used.max(t_used);
        table = odd_multiples(p);
    }
    let mut acc = Jacobian::INFINITY;
    for i in (0..used).rev() {
        if !acc.is_infinity() {
            acc = acc.double();
        }
        acc = add_wnaf_digit(&acc, s_digits[i], &G_ODD);
        acc = add_wnaf_digit(&acc, t_digits[i], &table);
    }
    acc
}

/// [k]P with public k and on-curve P, in variable time.
pub(crate) fn mul_public(point: &Affine, k: &Limbs) -> Jacobian {
    let (digits, used) = wnaf(k, VARIABLE_ODD_WIDTH);
    let table = odd_multiples(point);
    let mut acc = Jacobian::INFINITY;
    for i in (0..used).rev() {
        if !acc.is_infinity() {
            acc = acc.double();
        }
        acc = add_wnaf_digit(&acc, digits[i], &table);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::super::order::N;
    use super::super::point::{SM2_GX, SM2_GY};
    use super::*;

    const G: Affine = Affine {
        x: SM2_GX.value.limbs,
        y: SM2_GY.value.limbs,
    };

    fn scalar(seed: u64) -> Limbs {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        [next(), next(), next(), next()]
    }

    fn scalars() -> Vec<Limbs> {
        let mut all = vec![
            [0; 4],
            [1, 0, 0, 0],
            [2, 0, 0, 0],
            [u64::MAX; 4],
            N,
            [N[0] - 1, N[1], N[2], N[3]],
            [N[0] - 32, N[1], N[2], N[3]],
            [N[0] + 1, N[1], N[2], N[3]],
            [0, 0, 0, 1 << 63],
            [0, 1 << 63, 0, 0],
            [0x7fff_ffff, 0, 0, 0],
        ];
        all.extend((1..24).map(scalar));
        all
    }

    fn same(a: &Jacobian, b: &Jacobian) -> bool {
        match (a.to_affine(), b.to_affine()) {
            (None, None) => true,
            (Some(p), Some(q)) => p.x == q.x && p.y == q.y,
            _ => false,
        }
    }

    /// The recoded digits sum back to the scalar for every width in use.
    #[test]
    fn booth_digits_reassemble() {
        for k in scalars() {
            for width in [COMB_WIDTH, WIDTH] {
                let windows = 256 / width + 1;
                let mut acc = [0u64; 5];
                for index in (0..windows).rev() {
                    // acc = acc * 2^width + digit, on five limbs with wrap-around.
                    let mut carry = 0;
                    for limb in acc.iter_mut() {
                        let next = *limb >> (64 - width);
                        *limb = (*limb << width) | carry;
                        carry = next;
                    }
                    let (magnitude, negative) = booth_digit(&k, index, width as u32);
                    assert!(magnitude <= 1 << (width - 1));
                    let mut borrow_or_carry = magnitude;
                    for limb in acc.iter_mut() {
                        if negative != 0 {
                            let (v, b) = limb.overflowing_sub(borrow_or_carry);
                            *limb = v;
                            borrow_or_carry = b as u64;
                        } else {
                            let (v, c) = limb.overflowing_add(borrow_or_carry);
                            *limb = v;
                            borrow_or_carry = c as u64;
                        }
                    }
                }
                assert_eq!(acc, [k[0], k[1], k[2], k[3], 0], "width {width}");
            }
        }
    }

    #[test]
    fn wnaf_digits_reassemble() {
        for k in scalars() {
            for width in [G_ODD_WIDTH, VARIABLE_ODD_WIDTH] {
                let (digits, used) = wnaf(&k, width);
                let mut acc = [0u64; 5];
                for i in (0..257).rev() {
                    let mut carry = 0;
                    for limb in acc.iter_mut() {
                        let next = *limb >> 63;
                        *limb = (*limb << 1) | carry;
                        carry = next;
                    }
                    let d = digits[i];
                    assert!(i < used || d == 0);
                    if d != 0 {
                        assert!(d % 2 != 0);
                        assert!(i32::from(d).abs() < (1 << (width - 1)));
                    }
                    let mut rest = u64::from(d.unsigned_abs());
                    for limb in acc.iter_mut() {
                        let (v, c) = if d >= 0 {
                            limb.overflowing_add(rest)
                        } else {
                            limb.overflowing_sub(rest)
                        };
                        *limb = v;
                        rest = c as u64;
                    }
                }
                assert_eq!(acc, [k[0], k[1], k[2], k[3], 0], "width {width}");
            }
        }
    }

    /// All strategies give the same point on valid input.
    #[test]
    fn strategies_agree() {
        let p = mul_ct(&G, &scalar(100)).to_affine().unwrap();
        for k in scalars() {
            let reference = mul_ct(&p, &k);
            assert!(same(&mul_public(&p, &k), &reference), "public {k:x?}");
            assert!(same(&mul_base(&k), &mul_ct(&G, &k)), "fixed base {k:x?}");
            for s in [[0; 4], [1, 0, 0, 0], N, scalar(7), [u64::MAX; 4]] {
                let expected = mul_ct(&G, &s).add_vartime(&reference);
                assert!(
                    same(&mul_base_and_public(&s, &k, Some(&p)), &expected),
                    "joint {s:x?} {k:x?}"
                );
            }
            assert!(same(&mul_base_and_public(&k, &[0; 4], None), &mul_base(&k)));
        }
    }

    /// [s]G + [t]P where the two parts cancel or coincide.
    #[test]
    fn joint_multiplication_exceptional_cases() {
        let minus_g = G.negated();
        let one = [1, 0, 0, 0];
        assert!(mul_base_and_public(&one, &one, Some(&minus_g)).is_infinity());
        let twice = mul_base(&[2, 0, 0, 0]);
        assert!(same(&mul_base_and_public(&one, &one, Some(&G)), &twice));
        let three = [3, 0, 0, 0];
        assert!(same(
            &mul_base_and_public(&three, &[N[0] - 3, N[1], N[2], N[3]], Some(&G)),
            &Jacobian::INFINITY
        ));
    }

    /// The window-position argument: only the last addition may need the doubling case, so
    /// values that reach it there must come out right. k = n - 2j makes that happen.
    #[test]
    fn last_window_doubling_case() {
        for j in 1u64..=17 {
            let k = [N[0] - 2 * j, N[1], N[2], N[3]];
            let negated_multiple = mul_ct(&G, &[2 * j, 0, 0, 0]).to_affine().unwrap().negated();
            for actual in [mul_base(&k), mul_ct(&G, &k)] {
                let affine = actual.to_affine().unwrap();
                assert_eq!(affine.x, negated_multiple.x, "{j}");
                assert_eq!(affine.y, negated_multiple.y, "{j}");
            }
        }
    }
}
