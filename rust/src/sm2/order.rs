//! Arithmetic modulo the group order n, by Montgomery multiplication. Constant time.

use super::field::{Limbs, adc, add_limbs, mac, mul_wide, reduce_once, sbb, select, sub_limbs};

/// n, the order of the base point.
pub(crate) const N: Limbs = [
    0x53BB_F409_39D5_4123,
    0x7203_DF6B_21C6_052B,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFE_FFFF_FFFF,
];

/// -n^-1 mod 2^64, from Newton's iteration.
const N0: u64 = {
    let mut inv = 1u64;
    let mut i = 0;
    while i < 6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(N[0].wrapping_mul(inv)));
        i += 1;
    }
    inv.wrapping_neg()
};

/// R^2 mod n with R = 2^256, by repeated doubling of 1.
const R2: Limbs = {
    let mut r = [1u64, 0, 0, 0];
    let mut i = 0;
    while i < 512 {
        let (twice, carry) = add_limbs(&r, &r);
        let (reduced, borrow) = sub_limbs(&twice, &N);
        r = if carry != 0 || borrow == 0 {
            reduced
        } else {
            twice
        };
        i += 1;
    }
    r
};

/// Montgomery reduction T / R mod n, for T < n * R.
#[inline]
fn redc(t: &[u64; 8]) -> Limbs {
    let [t0, t1, t2, t3, t4, t5, t6, t7] = *t;

    let q = t0.wrapping_mul(N0);
    let (_, c) = mac(t0, q, N[0], 0);
    let (t1, c) = mac(t1, q, N[1], c);
    let (t2, c) = mac(t2, q, N[2], c);
    let (t3, c) = mac(t3, q, N[3], c);
    let (t4, top) = adc(t4, c, 0);

    let q = t1.wrapping_mul(N0);
    let (_, c) = mac(t1, q, N[0], 0);
    let (t2, c) = mac(t2, q, N[1], c);
    let (t3, c) = mac(t3, q, N[2], c);
    let (t4, c) = mac(t4, q, N[3], c);
    let (t5, top) = adc(t5, c, top);

    let q = t2.wrapping_mul(N0);
    let (_, c) = mac(t2, q, N[0], 0);
    let (t3, c) = mac(t3, q, N[1], c);
    let (t4, c) = mac(t4, q, N[2], c);
    let (t5, c) = mac(t5, q, N[3], c);
    let (t6, top) = adc(t6, c, top);

    let q = t3.wrapping_mul(N0);
    let (_, c) = mac(t3, q, N[0], 0);
    let (t4, c) = mac(t4, q, N[1], c);
    let (t5, c) = mac(t5, q, N[2], c);
    let (t6, c) = mac(t6, q, N[3], c);
    let (t7, top) = adc(t7, c, top);

    // The value is below 2n: subtract n when it carried or still is at least n.
    let (r0, b) = sbb(t4, N[0], 0);
    let (r1, b) = sbb(t5, N[1], b);
    let (r2, b) = sbb(t6, N[2], b);
    let (r3, b) = sbb(t7, N[3], b);
    let (_, b) = sbb(top, 0, b);
    select(b.wrapping_neg(), &[t4, t5, t6, t7], &[r0, r1, r2, r3])
}

/// a * b mod n for any 256-bit a and b; the result is canonical.
#[inline]
pub(crate) fn mul_mod_n(a: &Limbs, b: &Limbs) -> Limbs {
    let a = reduce_once(a, &N);
    let b = reduce_once(b, &N);
    let a_b_over_r = redc(&mul_wide(&a, &b));
    redc(&mul_wide(&a_b_over_r, &R2))
}

/// Any 256-bit value into [0, n). `n > 2^255`, so one subtraction is enough.
#[inline]
pub(crate) fn reduce_scalar(a: &Limbs) -> Limbs {
    reduce_once(a, &N)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn montgomery_constants() {
        // N0 * n = -1 mod 2^64
        assert_eq!(N0.wrapping_mul(N[0]), u64::MAX);
        // redc(R^2 * 1) = R mod n = 2^256 - n
        let r = redc(&mul_wide(&R2, &[1, 0, 0, 0]));
        assert_eq!(r, sub_limbs(&[0, 0, 0, 0], &N).0);
    }
}
