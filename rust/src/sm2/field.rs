//! Multi-limb primitives and arithmetic modulo the SM2 prime p, on plain little-endian limbs.
//!
//! No function branches on or indexes by its operands: conditional steps use masks from carries
//! (`select`).

pub(crate) use crate::ct::ct_barrier;

pub(crate) type Limbs = [u64; 4];

/// p = 2^256 - 2^224 - 2^96 + 2^64 - 1
pub(crate) const P: Limbs = [
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFE_FFFF_FFFF,
];

/// a + b + carry
#[inline(always)]
pub(crate) const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = a as u128 + b as u128 + carry as u128;
    (t as u64, (t >> 64) as u64)
}

/// a - b - borrow, with the outgoing borrow as 0 or 1.
#[inline(always)]
pub(crate) const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as u128).wrapping_sub(b as u128 + borrow as u128);
    (t as u64, ((t >> 64) as u64) & 1)
}

/// a + b * c + carry
#[inline(always)]
pub(crate) const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let t = a as u128 + (b as u128 * c as u128) + carry as u128;
    (t as u64, (t >> 64) as u64)
}

#[inline(always)]
pub(crate) const fn add_limbs(a: &Limbs, b: &Limbs) -> (Limbs, u64) {
    let (r0, c) = adc(a[0], b[0], 0);
    let (r1, c) = adc(a[1], b[1], c);
    let (r2, c) = adc(a[2], b[2], c);
    let (r3, c) = adc(a[3], b[3], c);
    ([r0, r1, r2, r3], c)
}

#[inline(always)]
pub(crate) const fn sub_limbs(a: &Limbs, b: &Limbs) -> (Limbs, u64) {
    let (r0, c) = sbb(a[0], b[0], 0);
    let (r1, c) = sbb(a[1], b[1], c);
    let (r2, c) = sbb(a[2], b[2], c);
    let (r3, c) = sbb(a[3], b[3], c);
    ([r0, r1, r2, r3], c)
}

/// `a` where the mask is all ones, `b` where it is zero.
#[inline(always)]
pub(crate) fn select(mask: u64, a: &Limbs, b: &Limbs) -> Limbs {
    let mask = ct_barrier(mask);
    [
        (a[0] & mask) | (b[0] & !mask),
        (a[1] & mask) | (b[1] & !mask),
        (a[2] & mask) | (b[2] & !mask),
        (a[3] & mask) | (b[3] & !mask),
    ]
}

/// All ones when the value is zero, otherwise zero.
#[inline(always)]
pub(crate) const fn is_zero_mask(a: &Limbs) -> u64 {
    let t = a[0] | a[1] | a[2] | a[3];
    ((t | t.wrapping_neg()) >> 63).wrapping_sub(1)
}

/// (a + b), minus the modulus once if that sum carried or reached it.
#[inline(always)]
pub(crate) fn add_mod(a: &Limbs, b: &Limbs, m: &Limbs) -> Limbs {
    let (sum, carry) = add_limbs(a, b);
    let (reduced, borrow) = sub_limbs(&sum, m);
    // Keep the unreduced sum only when there was no carry and the subtraction borrowed.
    let keep = (borrow & (carry ^ 1)).wrapping_neg();
    select(keep, &sum, &reduced)
}

/// (a - b), plus the modulus once if that borrowed.
#[inline(always)]
pub(crate) fn sub_mod(a: &Limbs, b: &Limbs, m: &Limbs) -> Limbs {
    let (diff, borrow) = sub_limbs(a, b);
    let mask = ct_barrier(borrow.wrapping_neg());
    let correction = [m[0] & mask, m[1] & mask, m[2] & mask, m[3] & mask];
    add_limbs(&diff, &correction).0
}

/// `a` minus `m` when `a >= m`. Fully reduces any 256-bit value when `m > 2^255`.
#[inline(always)]
pub(crate) fn reduce_once(a: &Limbs, m: &Limbs) -> Limbs {
    let (reduced, borrow) = sub_limbs(a, m);
    select(borrow.wrapping_neg(), a, &reduced)
}

/// Schoolbook 256 x 256 -> 512 bit product.
#[inline]
pub(crate) const fn mul_wide(a: &Limbs, b: &Limbs) -> [u64; 8] {
    let (r0, c) = mac(0, a[0], b[0], 0);
    let (r1, c) = mac(0, a[0], b[1], c);
    let (r2, c) = mac(0, a[0], b[2], c);
    let (r3, r4) = mac(0, a[0], b[3], c);

    let (r1, c) = mac(r1, a[1], b[0], 0);
    let (r2, c) = mac(r2, a[1], b[1], c);
    let (r3, c) = mac(r3, a[1], b[2], c);
    let (r4, r5) = mac(r4, a[1], b[3], c);

    let (r2, c) = mac(r2, a[2], b[0], 0);
    let (r3, c) = mac(r3, a[2], b[1], c);
    let (r4, c) = mac(r4, a[2], b[2], c);
    let (r5, r6) = mac(r5, a[2], b[3], c);

    let (r3, c) = mac(r3, a[3], b[0], 0);
    let (r4, c) = mac(r4, a[3], b[1], c);
    let (r5, c) = mac(r5, a[3], b[2], c);
    let (r6, r7) = mac(r6, a[3], b[3], c);

    [r0, r1, r2, r3, r4, r5, r6, r7]
}

/// Dedicated squaring: six cross products doubled, plus four squares.
#[inline]
pub(crate) const fn sqr_wide(a: &Limbs) -> [u64; 8] {
    let (r1, c) = mac(0, a[0], a[1], 0);
    let (r2, c) = mac(0, a[0], a[2], c);
    let (r3, r4) = mac(0, a[0], a[3], c);

    let (r3, c) = mac(r3, a[1], a[2], 0);
    let (r4, r5) = mac(r4, a[1], a[3], c);

    let (r5, r6) = mac(r5, a[2], a[3], 0);

    let r7 = r6 >> 63;
    let r6 = (r6 << 1) | (r5 >> 63);
    let r5 = (r5 << 1) | (r4 >> 63);
    let r4 = (r4 << 1) | (r3 >> 63);
    let r3 = (r3 << 1) | (r2 >> 63);
    let r2 = (r2 << 1) | (r1 >> 63);
    let r1 = r1 << 1;

    let (r0, c) = mac(0, a[0], a[0], 0);
    let (r1, c) = adc(r1, 0, c);
    let (r2, c) = mac(r2, a[1], a[1], c);
    let (r3, c) = adc(r3, 0, c);
    let (r4, c) = mac(r4, a[2], a[2], c);
    let (r5, c) = adc(r5, 0, c);
    let (r6, c) = mac(r6, a[3], a[3], c);
    let (r7, _) = adc(r7, 0, c);

    [r0, r1, r2, r3, r4, r5, r6, r7]
}

/// Solinas reduction of a 512-bit value modulo p, to the canonical range.
///
/// In 32-bit words w0..w15, each high word contributes its value at the positions of
/// 2^(32 k) mod p (k = 8..15), which sums to the signed columns below. The total is never
/// negative and stays below 2^260, so what remains above 2^256 folds away with
/// 2^256 = 2^224 + 2^96 - 2^64 + 1 (mod p) followed by one conditional subtraction.
#[inline]
pub(crate) fn reduce_wide_p(t: &[u64; 8]) -> Limbs {
    const LOW: u64 = 0xFFFF_FFFF;
    let w8 = (t[4] & LOW) as i64;
    let w9 = (t[4] >> 32) as i64;
    let w10 = (t[5] & LOW) as i64;
    let w11 = (t[5] >> 32) as i64;
    let w12 = (t[6] & LOW) as i64;
    let w13 = (t[6] >> 32) as i64;
    let w14 = (t[7] & LOW) as i64;
    let w15 = (t[7] >> 32) as i64;

    let s14_15 = w14 + w15;
    let s13_15 = w13 + s14_15;
    let s9_12 = w9 + w10 + w11 + w12;
    let all_low = s9_12 + w13 + s14_15;

    let c0 = (t[0] & LOW) as i64 + w8 + all_low + s13_15;
    let c1 = (t[0] >> 32) as i64 + all_low + s14_15;
    let c2 = (t[1] & LOW) as i64 - w8 - w9 - w13 - w14;
    let c3 = (t[1] >> 32) as i64 + w8 + w11 + w12 + w13 + s13_15;
    let c4 = (t[2] & LOW) as i64 + w9 + w12 + w13 + w14 + s14_15;
    let c5 = (t[2] >> 32) as i64 + w10 + s13_15 + w15;
    let c6 = (t[3] & LOW) as i64 + w11 + s14_15;
    let c7 = (t[3] >> 32) as i64 + w8 + all_low + w12 + s13_15 + w15;

    // Carry through the 32-bit columns; shifts are arithmetic, so c2's sign is handled.
    let c1 = c1 + (c0 >> 32);
    let c2 = c2 + (c1 >> 32);
    let c3 = c3 + (c2 >> 32);
    let c4 = c4 + (c3 >> 32);
    let c5 = c5 + (c4 >> 32);
    let c6 = c6 + (c5 >> 32);
    let c7 = c7 + (c6 >> 32);
    let overflow = (c7 >> 32) as u64;

    let m = LOW as i64;
    let low = [
        ((c0 & m) as u64) | (((c1 & m) as u64) << 32),
        ((c2 & m) as u64) | (((c3 & m) as u64) << 32),
        ((c4 & m) as u64) | (((c5 & m) as u64) << 32),
        ((c6 & m) as u64) | (((c7 & m) as u64) << 32),
    ];

    let (r, carry) = add_limbs(
        &low,
        &[overflow, (overflow << 32) - overflow, 0, overflow << 32],
    );
    // A carry here leaves r small, so this second fold cannot carry again.
    let (r, _) = add_limbs(&r, &[carry, (carry << 32) - carry, 0, carry << 32]);
    reduce_once(&r, &P)
}

#[inline]
pub(crate) fn fe_mul(a: &Limbs, b: &Limbs) -> Limbs {
    reduce_wide_p(&mul_wide(a, b))
}

#[inline]
pub(crate) fn fe_sqr(a: &Limbs) -> Limbs {
    reduce_wide_p(&sqr_wide(a))
}

#[inline(always)]
pub(crate) fn fe_add(a: &Limbs, b: &Limbs) -> Limbs {
    add_mod(a, b, &P)
}

#[inline(always)]
pub(crate) fn fe_sub(a: &Limbs, b: &Limbs) -> Limbs {
    sub_mod(a, b, &P)
}

#[inline(always)]
pub(crate) fn fe_dbl(a: &Limbs) -> Limbs {
    add_mod(a, a, &P)
}

/// -a mod p, canonical (zero stays zero).
#[inline(always)]
pub(crate) fn fe_neg(a: &Limbs) -> Limbs {
    fe_sub(&[0; 4], a)
}
