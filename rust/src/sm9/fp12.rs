//! Fq12 = Fq4[w]/(w^3 - v), the GT arithmetic, and the constant-time GT exponentiation.
//!
//! Coefficient k of w^k in the six-term view (w^6 = u) is: k = 0, 1, 2 the `c0` half of
//! c0, c1, c2 and k = 3, 4, 5 their `c1` half, because w^3 = v.

use super::fp::{Fp, Limbs};
use super::tower::{Fp2, Fp4};
use crate::ct::ct_barrier;

/// c0 + c1 w + c2 w^2
#[derive(Clone, Copy)]
pub(crate) struct Fp12 {
    pub(crate) c0: Fp4,
    pub(crate) c1: Fp4,
    pub(crate) c2: Fp4,
}

/// Frobenius constants u^(k (q^e - 1) / 6) for k = 1..5, all in Fq (index 0 unused).
const fn frob_row(raw: [Limbs; 5]) -> [Fp; 6] {
    [
        Fp::ONE,
        Fp::from_raw(raw[0]),
        Fp::from_raw(raw[1]),
        Fp::from_raw(raw[2]),
        Fp::from_raw(raw[3]),
        Fp::from_raw(raw[4]),
    ]
}

const FROB1: [Fp; 6] = frob_row([
    [
        0xa91d8354377b698b,
        0x47c5c86e0ddd04ed,
        0x843c6cfa9c086749,
        0x3f23ea58e5720bdb,
    ],
    [
        0xd5fc11967be65334,
        0x780272354f8b78f4,
        0xf300000002a3a6f2,
        0x0000000000000000,
    ],
    [
        0xf5b21fd3da24d011,
        0x9f9d411806dc5177,
        0xf55acc93ee0baf15,
        0x6c648de5dc0a3f2c,
    ],
    [
        0xd5fc11967be65333,
        0x780272354f8b78f4,
        0xf300000002a3a6f2,
        0x0000000000000000,
    ],
    [
        0x4c949c7fa2a96686,
        0x57d778a9f8ff4c8a,
        0x711e5f99520347cc,
        0x2d40a38cf6983351,
    ],
]);
const FROB2: [Fp; 6] = frob_row([
    [
        0xd5fc11967be65334,
        0x780272354f8b78f4,
        0xf300000002a3a6f2,
        0x0000000000000000,
    ],
    [
        0xd5fc11967be65333,
        0x780272354f8b78f4,
        0xf300000002a3a6f2,
        0x0000000000000000,
    ],
    [
        0xe56f9b27e351457c,
        0x21f2934b1a7aeedb,
        0xd603ab4ff58ec745,
        0xb640000002a3a6f1,
    ],
    [
        0x0f738991676af249,
        0xa9f02115caef75e7,
        0xe303ab4ff2eb2052,
        0xb640000002a3a6f0,
    ],
    [
        0x0f738991676af24a,
        0xa9f02115caef75e7,
        0xe303ab4ff2eb2052,
        0xb640000002a3a6f0,
    ],
]);
const FROB3: [Fp; 6] = frob_row([
    [
        0xf5b21fd3da24d011,
        0x9f9d411806dc5177,
        0xf55acc93ee0baf15,
        0x6c648de5dc0a3f2c,
    ],
    [
        0xe56f9b27e351457c,
        0x21f2934b1a7aeedb,
        0xd603ab4ff58ec745,
        0xb640000002a3a6f1,
    ],
    [
        0xefbd7b54092c756c,
        0x82555233139e9d63,
        0xe0a8debc0783182f,
        0x49db721a269967c4,
    ],
    [
        0x0000000000000001,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ],
    [
        0xf5b21fd3da24d011,
        0x9f9d411806dc5177,
        0xf55acc93ee0baf15,
        0x6c648de5dc0a3f2c,
    ],
]);

/// The BN parameter t, which drives the hard part of the final exponentiation.
const T: u64 = 0x6000_0000_0058_f98a;

/// Width of the signed windows of the GT exponentiation.
const WIDTH: usize = 5;
const WINDOWS: usize = 256 / WIDTH + 1;
const ENTRIES: usize = 1 << (WIDTH - 1);

/// Bytes of the GT encoding.
pub(crate) const GT_BYTES: usize = 384;

impl Fp12 {
    pub(crate) const ONE: Fp12 = Fp12::new(Fp4::ONE, Fp4::ZERO, Fp4::ZERO);

    pub(crate) const fn new(c0: Fp4, c1: Fp4, c2: Fp4) -> Fp12 {
        Fp12 { c0, c1, c2 }
    }

    /// Karatsuba over the cubic extension: six multiplications in Fq4.
    pub(crate) fn mul(&self, b: &Fp12) -> Fp12 {
        let a = self;
        let v0 = a.c0.mul(&b.c0);
        let v1 = a.c1.mul(&b.c1);
        let v2 = a.c2.mul(&b.c2);
        let t12 = a.c1.add(&a.c2).mul(&b.c1.add(&b.c2)).sub(&v1).sub(&v2);
        let t01 = a.c0.add(&a.c1).mul(&b.c0.add(&b.c1)).sub(&v0).sub(&v1);
        let t02 = a.c0.add(&a.c2).mul(&b.c0.add(&b.c2)).sub(&v0).sub(&v2);
        Fp12::new(v0.add(&t12.mul_v()), t01.add(&v2.mul_v()), t02.add(&v1))
    }

    /// Chung-Hasan SQR2: three squarings and two multiplications in Fq4.
    pub(crate) fn sqr(&self) -> Fp12 {
        let (a0, a1, a2) = (&self.c0, &self.c1, &self.c2);
        let s0 = a0.sqr();
        let s1 = a0.mul(a1).dbl();
        let s2 = a0.sub(a1).add(a2).sqr();
        let s3 = a1.mul(a2).dbl();
        let s4 = a2.sqr();
        Fp12::new(
            s0.add(&s3.mul_v()),
            s1.add(&s4.mul_v()),
            s1.add(&s2).add(&s3).sub(&s0).sub(&s4),
        )
    }

    /// Granger-Scott squaring, valid in the cyclotomic subgroup (after the easy part).
    pub(crate) fn cyclotomic_sqr(&self) -> Fp12 {
        let (a0, a1, a2) = (&self.c0, &self.c1, &self.c2);
        let three = |x: Fp4| x.dbl().add(&x);
        let c0 = three(a0.sqr()).sub(&a0.conj().dbl());
        let c1 = three(a2.sqr().mul_v()).add(&a1.conj().dbl());
        let c2 = three(a1.sqr()).sub(&a2.conj().dbl());
        Fp12::new(c0, c1, c2)
    }

    /// x^(q^6), which is the inverse in the cyclotomic subgroup.
    #[inline]
    pub(crate) fn conj(&self) -> Fp12 {
        Fp12::new(self.c0.conj(), self.c1.conj().neg(), self.c2.conj())
    }

    pub(crate) fn invert(&self) -> Fp12 {
        let (a0, a1, a2) = (&self.c0, &self.c1, &self.c2);
        let t0 = a0.sqr().sub(&a1.mul(a2).mul_v());
        let t1 = a2.sqr().mul_v().sub(&a0.mul(a1));
        let t2 = a1.sqr().sub(&a0.mul(a2));
        let norm = a0.mul(&t0).add(&a2.mul(&t1).add(&a1.mul(&t2)).mul_v());
        let inv = norm.invert();
        Fp12::new(t0.mul(&inv), t1.mul(&inv), t2.mul(&inv))
    }

    /// x^(q^e) for e = 1, 2, 3: coefficient k becomes x_k (conjugated for odd e) times gamma^k.
    pub(crate) fn frobenius(&self, e: usize) -> Fp12 {
        let (gamma, conj) = match e {
            1 => (&FROB1, true),
            2 => (&FROB2, false),
            _ => (&FROB3, true),
        };
        let map = |x: &Fp2, k: usize| {
            let x = if conj { x.conj() } else { *x };
            if k == 0 { x } else { x.mul_fp(&gamma[k]) }
        };
        Fp12::new(
            Fp4::new(map(&self.c0.c0, 0), map(&self.c0.c1, 3)),
            Fp4::new(map(&self.c1.c0, 1), map(&self.c1.c1, 4)),
            Fp4::new(map(&self.c2.c0, 2), map(&self.c2.c1, 5)),
        )
    }

    /// Multiplies by a sparse line b0 + l2 w^2 (b0 in Fq4, l2 in Fq2): 15 Fq2 multiplications
    /// instead of 18.
    pub(crate) fn mul_by_line(&self, b0: &Fp4, l2: &Fp2) -> Fp12 {
        let (a0, a1, a2) = (&self.c0, &self.c1, &self.c2);
        Fp12::new(
            a0.mul(b0).add(&a1.mul_fp2(l2).mul_v()),
            a1.mul(b0).add(&a2.mul_fp2(l2).mul_v()),
            a2.mul(b0).add(&a0.mul_fp2(l2)),
        )
    }

    pub(crate) fn select(mask: u64, a: &Fp12, b: &Fp12) -> Fp12 {
        Fp12::new(
            Fp4::select(mask, &a.c0, &b.c0),
            Fp4::select(mask, &a.c1, &b.c1),
            Fp4::select(mask, &a.c2, &b.c2),
        )
    }

    /// c2 || c1 || c0, each Fq4 as c1 || c0, each Fq2 as a1 || a0.
    pub(crate) fn to_bytes(self) -> [u8; GT_BYTES] {
        let mut out = [0u8; GT_BYTES];
        for (chunk, c) in out
            .chunks_exact_mut(128)
            .zip([&self.c2, &self.c1, &self.c0])
        {
            c.c1.write_be(&mut chunk[..64]);
            c.c0.write_be(&mut chunk[64..]);
        }
        out
    }

    /// x^t in the cyclotomic subgroup; t is public.
    fn pow_t(&self) -> Fp12 {
        let mut acc = *self;
        for bit in (0..(63 - T.leading_zeros())).rev() {
            acc = acc.cyclotomic_sqr();
            if (T >> bit) & 1 == 1 {
                acc = acc.mul(self);
            }
        }
        acc
    }

    /// f^((q^12 - 1) / N): easy part (q^6 - 1)(q^2 + 1), then the BN hard part
    /// (q^4 - q^2 + 1) / N = l0 + l1 q + l2 q^2 + q^3 through t (Scott et al.).
    pub(crate) fn final_exponentiation(&self) -> Fp12 {
        let f = self.conj().mul(&self.invert());
        let f = f.frobenius(2).mul(&f);

        let a = f.pow_t();
        let b = a.pow_t();
        let c = b.pow_t();
        let y0 = f.frobenius(1).mul(&f.frobenius(2)).mul(&f.frobenius(3));
        let y1 = f.conj();
        let y2 = b.frobenius(2);
        let y3 = a.frobenius(1).conj();
        let y4 = a.mul(&b.frobenius(1)).conj();
        let y5 = b.conj();
        let y6 = c.mul(&c.frobenius(1)).conj();

        // y0 y1^2 y2^6 y3^12 y4^18 y5^30 y6^36
        let mut t0 = y6.cyclotomic_sqr().mul(&y4).mul(&y5);
        let mut t1 = y3.mul(&y5).mul(&t0);
        t0 = t0.mul(&y2);
        t1 = t1.cyclotomic_sqr().mul(&t0).cyclotomic_sqr();
        t0 = t1.mul(&y1);
        t1 = t1.mul(&y0);
        t0.cyclotomic_sqr().mul(&t1)
    }

    /// x^k for x in GT and any 256-bit k, with a regular schedule: signed fixed windows and a
    /// masked scan of the whole table, so neither branches nor addresses depend on k.
    pub(crate) fn pow_ct(&self, k: &Limbs) -> Fp12 {
        let mut table = [Fp12::ONE; ENTRIES + 1];
        table[1] = *self;
        table[2] = self.cyclotomic_sqr();
        for i in 3..=ENTRIES {
            table[i] = table[i - 1].mul(self);
        }
        let mut acc = Fp12::ONE;
        for index in (0..WINDOWS).rev() {
            if index != WINDOWS - 1 {
                for _ in 0..WIDTH {
                    acc = acc.cyclotomic_sqr();
                }
            }
            let (magnitude, negative) = booth_digit(k, index, WIDTH as u32);
            let mut entry = Fp12::ONE;
            for (i, candidate) in table.iter().enumerate() {
                entry = Fp12::select(eq_mask(i as u64, magnitude), candidate, &entry);
            }
            entry = Fp12::select(negative, &entry.conj(), &entry);
            acc = acc.mul(&entry);
        }
        acc
    }

    /// Equality for public values.
    #[cfg(test)]
    pub(crate) fn eq_vartime(&self, other: &Fp12) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

/// Bits `[start, start + count)` of k, count <= 57; bits beyond 255 read as zero.
#[inline(always)]
pub(crate) fn bits(k: &Limbs, start: usize, count: u32) -> u64 {
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
pub(crate) fn eq_mask(a: u64, b: u64) -> u64 {
    let d = a ^ b;
    ct_barrier(((d | d.wrapping_neg()) >> 63).wrapping_sub(1))
}

/// Booth digit of window `index` as (magnitude, negative mask), magnitude <= 2^(width-1).
/// The window positions are public; only the digit values are secret.
#[inline(always)]
pub(crate) fn booth_digit(k: &Limbs, index: usize, width: u32) -> (u64, u64) {
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
