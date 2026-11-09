//! Arithmetic modulo the SM9 prime q (Montgomery form) and modulo the group order N.
//!
//! Both moduli are generic 256-bit primes above 2^255, so one Montgomery multiplication (CIOS on
//! four u64 limbs with u128 intermediates) serves both. Nothing here branches on or indexes by an
//! operand: conditional steps are masks from carries, hidden from the optimizer by `ct_barrier`.

use crate::ct::ct_barrier;

pub(crate) type Limbs = [u64; 4];

/// q = 36t^4 + 36t^3 + 24t^2 + 6t + 1
pub(crate) const Q: Limbs = [
    0xe56f_9b27_e351_457d,
    0x21f2_934b_1a7a_eedb,
    0xd603_ab4f_f58e_c745,
    0xb640_0000_02a3_a6f1,
];
/// -q^-1 mod 2^64
const Q_INV: u64 = 0x892b_c42c_2f2e_e42b;
/// 2^512 mod q
const Q_R2: Limbs = [
    0x27de_a312_b417_e2d2,
    0x88f8_105f_ae1a_5d3f,
    0xe479_b522_d670_6e7b,
    0x2ea7_95a6_56f6_2fbd,
];

/// N = 36t^4 + 36t^3 + 18t^2 + 6t + 1, the order of G1, G2 and GT.
pub(crate) const N: Limbs = [
    0xe56e_e19c_d69e_cf25,
    0x49f2_934b_18ea_8bee,
    0xd603_ab4f_f58e_c744,
    0xb640_0000_02a3_a6f1,
];
const N_INV: u64 = 0x1d02_6623_5197_4b53;
const N_R2: Limbs = [
    0x7598_cd79_cd75_0c35,
    0xe4a0_8110_bb6d_aeab,
    0xbfee_4bae_7d78_a1f9,
    0x8894_f5d1_6369_5d0e,
];
/// N - 1, the modulus of the hash-to-range step.
pub(crate) const N_MINUS_1: Limbs = [N[0] - 1, N[1], N[2], N[3]];

#[inline(always)]
const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = a as u128 + b as u128 + carry as u128;
    (t as u64, (t >> 64) as u64)
}

#[inline(always)]
const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as u128).wrapping_sub(b as u128 + borrow as u128);
    (t as u64, ((t >> 64) as u64) & 1)
}

#[inline(always)]
const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
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

/// All ones when the value is zero.
#[inline(always)]
pub(crate) fn is_zero_mask(a: &Limbs) -> u64 {
    let t = a[0] | a[1] | a[2] | a[3];
    ct_barrier(((t | t.wrapping_neg()) >> 63).wrapping_sub(1))
}

/// True when a < m (public values only: this returns a bool).
#[inline]
pub(crate) fn less_than(a: &Limbs, m: &Limbs) -> bool {
    sub_limbs(a, m).1 == 1
}

/// The value `hi * 2^256 + lo` (below 2m), reduced once.
#[inline(always)]
const fn reduce_carry(lo: Limbs, hi: u64, m: &Limbs) -> Limbs {
    let (r, borrow) = sub_limbs(&lo, m);
    // Keep the unreduced value only when it had no carry and the subtraction borrowed.
    let keep = (borrow & (hi ^ 1)).wrapping_neg();
    [
        (lo[0] & keep) | (r[0] & !keep),
        (lo[1] & keep) | (r[1] & !keep),
        (lo[2] & keep) | (r[2] & !keep),
        (lo[3] & keep) | (r[3] & !keep),
    ]
}

#[inline(always)]
pub(crate) fn add_mod(a: &Limbs, b: &Limbs, m: &Limbs) -> Limbs {
    let (sum, carry) = add_limbs(a, b);
    let (r, borrow) = sub_limbs(&sum, m);
    let keep = ct_barrier((borrow & (carry ^ 1)).wrapping_neg());
    select(keep, &sum, &r)
}

#[inline(always)]
pub(crate) fn sub_mod(a: &Limbs, b: &Limbs, m: &Limbs) -> Limbs {
    let (diff, borrow) = sub_limbs(a, b);
    let mask = ct_barrier(borrow.wrapping_neg());
    let correction = [m[0] & mask, m[1] & mask, m[2] & mask, m[3] & mask];
    add_limbs(&diff, &correction).0
}

/// a * b / 2^256 mod m, for a, b < m < 2^256 and odd m (CIOS).
#[inline(always)]
const fn mont_mul(a: &Limbs, b: &Limbs, m: &Limbs, m_inv: u64) -> Limbs {
    let mut t = [0u64; 6];
    let mut i = 0;
    while i < 4 {
        let (t0, c) = mac(t[0], a[i], b[0], 0);
        let (t1, c) = mac(t[1], a[i], b[1], c);
        let (t2, c) = mac(t[2], a[i], b[2], c);
        let (t3, c) = mac(t[3], a[i], b[3], c);
        let (t4, t5) = adc(t[4], c, 0);
        let k = t0.wrapping_mul(m_inv);
        let (_, c) = mac(t0, k, m[0], 0);
        let (r0, c) = mac(t1, k, m[1], c);
        let (r1, c) = mac(t2, k, m[2], c);
        let (r2, c) = mac(t3, k, m[3], c);
        let (r3, c) = adc(t4, c, 0);
        t = [r0, r1, r2, r3, t5 + c, 0];
        i += 1;
    }
    reduce_carry([t[0], t[1], t[2], t[3]], t[4], m)
}

/// An element of Fq in Montgomery form, fully reduced.
#[derive(Clone, Copy)]
pub(crate) struct Fp(pub(crate) Limbs);

impl Fp {
    pub(crate) const ZERO: Fp = Fp([0; 4]);
    pub(crate) const ONE: Fp = Fp::from_raw([1, 0, 0, 0]);

    /// From a plain value below q; usable in constants.
    pub(crate) const fn from_raw(value: Limbs) -> Fp {
        Fp(mont_mul(&value, &Q_R2, &Q, Q_INV))
    }

    pub(crate) const fn to_raw(self) -> Limbs {
        mont_mul(&self.0, &[1, 0, 0, 0], &Q, Q_INV)
    }

    /// Big-endian bytes; `None` unless the value is below q.
    pub(crate) fn from_be_bytes(bytes: &[u8]) -> Option<Fp> {
        let value = limbs_from_be(bytes);
        less_than(&value, &Q).then(|| Fp::from_raw(value))
    }

    pub(crate) fn to_be_bytes(self) -> [u8; 32] {
        limbs_to_be(&self.to_raw())
    }

    #[inline(always)]
    pub(crate) fn add(&self, other: &Fp) -> Fp {
        Fp(add_mod(&self.0, &other.0, &Q))
    }

    #[inline(always)]
    pub(crate) fn sub(&self, other: &Fp) -> Fp {
        Fp(sub_mod(&self.0, &other.0, &Q))
    }

    #[inline(always)]
    pub(crate) fn dbl(&self) -> Fp {
        self.add(self)
    }

    #[inline(always)]
    pub(crate) fn neg(&self) -> Fp {
        Fp::ZERO.sub(self)
    }

    #[inline(always)]
    pub(crate) fn mul(&self, other: &Fp) -> Fp {
        Fp(mont_mul(&self.0, &other.0, &Q, Q_INV))
    }

    #[inline(always)]
    pub(crate) fn sqr(&self) -> Fp {
        self.mul(self)
    }

    /// a^(q-2), with the public exponent: constant time in a. Zero maps to zero.
    pub(crate) fn invert(&self) -> Fp {
        let mut exp = Q;
        exp[0] -= 2;
        let mut acc = Fp::ONE;
        for bit in (0..256).rev() {
            acc = acc.sqr();
            if (exp[bit / 64] >> (bit % 64)) & 1 == 1 {
                acc = acc.mul(self);
            }
        }
        acc
    }

    #[inline(always)]
    pub(crate) fn is_zero_mask(&self) -> u64 {
        is_zero_mask(&self.0)
    }

    #[inline(always)]
    pub(crate) fn select(mask: u64, a: &Fp, b: &Fp) -> Fp {
        Fp(select(mask, &a.0, &b.0))
    }
}

/// Big-endian bytes (at most 32) to little-endian limbs.
pub(crate) fn limbs_from_be(bytes: &[u8]) -> Limbs {
    debug_assert!(bytes.len() <= 32);
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().rev().zip(padded.chunks_exact(8)) {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        *limb = u64::from_be_bytes(word);
    }
    limbs
}

pub(crate) fn limbs_to_be(limbs: &Limbs) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, limb) in out.chunks_exact_mut(8).zip(limbs.iter().rev()) {
        chunk.copy_from_slice(&limb.to_be_bytes());
    }
    out
}

/// An integer modulo N in plain (not Montgomery) form, fully reduced.
#[derive(Clone, Copy)]
pub(crate) struct Scalar(pub(crate) Limbs);

impl Scalar {
    pub(crate) const ZERO: Scalar = Scalar([0; 4]);

    /// 32 big-endian bytes; `None` outside [1, N-1].
    pub(crate) fn from_be_bytes_nonzero(bytes: &[u8; 32]) -> Option<Scalar> {
        let value = limbs_from_be(bytes);
        let in_range = less_than(&value, &N) && is_zero_mask(&value) == 0;
        in_range.then_some(Scalar(value))
    }

    pub(crate) fn to_be_bytes(self) -> [u8; 32] {
        limbs_to_be(&self.0)
    }

    #[inline]
    pub(crate) fn add(&self, other: &Scalar) -> Scalar {
        Scalar(add_mod(&self.0, &other.0, &N))
    }

    #[inline]
    pub(crate) fn sub(&self, other: &Scalar) -> Scalar {
        Scalar(sub_mod(&self.0, &other.0, &N))
    }

    #[inline]
    pub(crate) fn mul(&self, other: &Scalar) -> Scalar {
        let t = mont_mul(&self.0, &other.0, &N, N_INV);
        Scalar(mont_mul(&t, &N_R2, &N, N_INV))
    }

    /// a^(N-2) in Montgomery form, constant time in a. Zero maps to zero.
    pub(crate) fn invert(&self) -> Scalar {
        let base = mont_mul(&self.0, &N_R2, &N, N_INV);
        let mut exp = N;
        exp[0] -= 2;
        let mut acc = mont_mul(&[1, 0, 0, 0], &N_R2, &N, N_INV);
        for bit in (0..256).rev() {
            acc = mont_mul(&acc, &acc, &N, N_INV);
            if (exp[bit / 64] >> (bit % 64)) & 1 == 1 {
                acc = mont_mul(&acc, &base, &N, N_INV);
            }
        }
        Scalar(mont_mul(&acc, &[1, 0, 0, 0], &N, N_INV))
    }

    /// Whether the value is zero; the result is a public decision.
    pub(crate) fn is_zero(&self) -> bool {
        ct_barrier(is_zero_mask(&self.0)) != 0
    }
}

/// (x mod (N - 1)) + 1 for a 320-bit big-endian x: the range step of H1 and H2. Public data.
pub(crate) fn hash_to_range(bytes: &[u8; 40]) -> Scalar {
    let m = N_MINUS_1;
    // The top 256 bits are below 2m, so one subtraction reduces them.
    let top = limbs_from_be(&bytes[..32]);
    let mut r = reduce_carry(top, 0, &m);
    for &byte in &bytes[32..] {
        for bit in (0..8).rev() {
            // r = 2r + bit, below 2m < 2^257
            let carry = r[3] >> 63;
            let shifted = [
                (r[0] << 1) | u64::from((byte >> bit) & 1),
                (r[1] << 1) | (r[0] >> 63),
                (r[2] << 1) | (r[1] >> 63),
                (r[3] << 1) | (r[2] >> 63),
            ];
            r = reduce_carry(shifted, carry, &m);
        }
    }
    Scalar(add_limbs(&r, &[1, 0, 0, 0]).0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn montgomery_round_trip_and_inverse() {
        let x = Fp::from_raw([5, 6, 7, 8]);
        assert_eq!(x.to_raw(), [5, 6, 7, 8]);
        let one = x.mul(&x.invert());
        assert_eq!(one.to_raw(), [1, 0, 0, 0]);
        assert_eq!(Fp::ONE.neg().add(&Fp::ONE).to_raw(), [0; 4]);
        let s = Scalar([9, 1, 2, 3]);
        assert_eq!(s.mul(&s.invert()).0, [1, 0, 0, 0]);
        assert_eq!(Scalar::ZERO.invert().0, [0; 4]);
    }

    #[test]
    fn hash_range_reduces() {
        let r = hash_to_range(&[0xff; 40]);
        assert!(less_than(&r.0, &N));
        let mut small = [0u8; 40];
        small[39] = 7;
        assert_eq!(hash_to_range(&small).0, [8, 0, 0, 0]);
    }
}
