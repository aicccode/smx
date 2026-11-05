//! Jacobian point arithmetic for y^2 = x^3 - 3x + b, on raw field limbs.
//!
//! (X, Y, Z) stands for the affine point (X/Z^2, Y/Z^3), and Z = 0 for infinity. The formulas do
//! not use b, which is why every input must be checked to be on the curve first.

use super::field::{Limbs, fe_add, fe_dbl, fe_mul, fe_neg, fe_sqr, fe_sub, is_zero_mask, select};
use super::modinv::{MOD_P, invert};

#[derive(Clone, Copy)]
pub(crate) struct Affine {
    pub(crate) x: Limbs,
    pub(crate) y: Limbs,
}

#[derive(Clone, Copy)]
pub(crate) struct Jacobian {
    pub(crate) x: Limbs,
    pub(crate) y: Limbs,
    pub(crate) z: Limbs,
}

const ONE: Limbs = [1, 0, 0, 0];

impl Affine {
    pub(crate) const ZERO: Affine = Affine {
        x: [0; 4],
        y: [0; 4],
    };

    #[inline(always)]
    pub(crate) fn to_jacobian(self) -> Jacobian {
        Jacobian {
            x: self.x,
            y: self.y,
            z: ONE,
        }
    }

    #[inline(always)]
    pub(crate) fn negated(self) -> Affine {
        Affine {
            x: self.x,
            y: fe_neg(&self.y),
        }
    }
}

impl Jacobian {
    pub(crate) const INFINITY: Jacobian = Jacobian {
        x: ONE,
        y: ONE,
        z: [0; 4],
    };

    #[inline(always)]
    pub(crate) fn is_infinity(&self) -> bool {
        is_zero_mask(&self.z) != 0
    }

    #[inline(always)]
    fn select(mask: u64, a: &Jacobian, b: &Jacobian) -> Jacobian {
        Jacobian {
            x: select(mask, &a.x, &b.x),
            y: select(mask, &a.y, &b.y),
            z: select(mask, &a.z, &b.z),
        }
    }

    /// dbl-2001-b for a = -3: 3M + 5S. Infinity (and y = 0) yields Z = 0 without special casing.
    #[inline]
    pub(crate) fn double(&self) -> Jacobian {
        let delta = fe_sqr(&self.z);
        let gamma = fe_sqr(&self.y);
        let beta = fe_mul(&self.x, &gamma);
        let product = fe_mul(&fe_sub(&self.x, &delta), &fe_add(&self.x, &delta));
        let alpha = fe_add(&fe_dbl(&product), &product);
        let beta4 = fe_dbl(&fe_dbl(&beta));
        let x3 = fe_sub(&fe_sqr(&alpha), &fe_dbl(&beta4));
        let z3 = fe_sub(&fe_sub(&fe_sqr(&fe_add(&self.y, &self.z)), &gamma), &delta);
        let gamma2 = fe_sqr(&gamma);
        let y3 = fe_sub(
            &fe_mul(&alpha, &fe_sub(&beta4, &x3)),
            &fe_dbl(&fe_dbl(&fe_dbl(&gamma2))),
        );
        Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// The addition formula with Z2 = 1 (8M + 3S), valid when neither input is infinity and
    /// H = 0 does not occur together with R = 0. Returns H and R for those checks; for H = 0 and
    /// R != 0 (P + (-P)) the result already has Z = 0.
    #[inline]
    fn add_mixed_raw(&self, other: &Affine) -> (Jacobian, Limbs, Limbs) {
        let z1z1 = fe_sqr(&self.z);
        let u2 = fe_mul(&other.x, &z1z1);
        let s2 = fe_mul(&fe_mul(&other.y, &self.z), &z1z1);
        let h = fe_sub(&u2, &self.x);
        let r = fe_sub(&s2, &self.y);
        let hh = fe_sqr(&h);
        let hhh = fe_mul(&hh, &h);
        let v = fe_mul(&self.x, &hh);
        let x3 = fe_sub(&fe_sub(&fe_sqr(&r), &hhh), &fe_dbl(&v));
        let y3 = fe_sub(&fe_mul(&r, &fe_sub(&v, &x3)), &fe_mul(&self.y, &hhh));
        let z3 = fe_mul(&self.z, &h);
        (
            Jacobian {
                x: x3,
                y: y3,
                z: z3,
            },
            h,
            r,
        )
    }

    /// General addition formula (12M + 4S); same contract as `add_mixed_raw`.
    #[inline]
    fn add_raw(&self, other: &Jacobian) -> (Jacobian, Limbs, Limbs) {
        let z1z1 = fe_sqr(&self.z);
        let z2z2 = fe_sqr(&other.z);
        let u1 = fe_mul(&self.x, &z2z2);
        let u2 = fe_mul(&other.x, &z1z1);
        let s1 = fe_mul(&fe_mul(&self.y, &other.z), &z2z2);
        let s2 = fe_mul(&fe_mul(&other.y, &self.z), &z1z1);
        let h = fe_sub(&u2, &u1);
        let r = fe_sub(&s2, &s1);
        let hh = fe_sqr(&h);
        let hhh = fe_mul(&hh, &h);
        let v = fe_mul(&u1, &hh);
        let x3 = fe_sub(&fe_sub(&fe_sqr(&r), &hhh), &fe_dbl(&v));
        let y3 = fe_sub(&fe_mul(&r, &fe_sub(&v, &x3)), &fe_mul(&s1, &hhh));
        let z3 = fe_mul(&fe_mul(&self.z, &other.z), &h);
        (
            Jacobian {
                x: x3,
                y: y3,
                z: z3,
            },
            h,
            r,
        )
    }

    /// Constant-time `self + other` where `other_is_infinity` is a mask.
    ///
    /// With `exceptional` false, the caller guarantees that self != other unless one of them is
    /// infinity. With it true the doubling case is also computed and selected. That flag only
    /// ever depends on a public fact: the position in the scalar.
    #[inline]
    pub(crate) fn add_mixed_ct(
        &self,
        other: &Affine,
        other_is_infinity: u64,
        exceptional: bool,
    ) -> Jacobian {
        let (mut out, h, r) = self.add_mixed_raw(other);
        if exceptional {
            let same = is_zero_mask(&h) & is_zero_mask(&r);
            out = Jacobian::select(same, &self.double(), &out);
        }
        out = Jacobian::select(is_zero_mask(&self.z), &other.to_jacobian(), &out);
        Jacobian::select(other_is_infinity, self, &out)
    }

    /// Constant-time general addition; infinity inputs are recognized from their Z limbs.
    /// `exceptional` as for `add_mixed_ct`.
    #[inline]
    pub(crate) fn add_ct(&self, other: &Jacobian, exceptional: bool) -> Jacobian {
        let (mut out, h, r) = self.add_raw(other);
        if exceptional {
            let same = is_zero_mask(&h) & is_zero_mask(&r);
            out = Jacobian::select(same, &self.double(), &out);
        }
        out = Jacobian::select(is_zero_mask(&self.z), other, &out);
        Jacobian::select(is_zero_mask(&other.z), self, &out)
    }

    /// Variable-time mixed addition handling every case by branching. Public data only.
    #[inline]
    pub(crate) fn add_mixed_vartime(&self, other: &Affine) -> Jacobian {
        if self.is_infinity() {
            return other.to_jacobian();
        }
        let (out, h, r) = self.add_mixed_raw(other);
        if is_zero_mask(&h) != 0 && is_zero_mask(&r) != 0 {
            return self.double();
        }
        out
    }

    /// Variable-time general addition handling every case by branching. Public data only.
    pub(crate) fn add_vartime(&self, other: &Jacobian) -> Jacobian {
        if self.is_infinity() {
            return *other;
        }
        if other.is_infinity() {
            return *self;
        }
        let (out, h, r) = self.add_raw(other);
        if is_zero_mask(&h) != 0 && is_zero_mask(&r) != 0 {
            return self.double();
        }
        out
    }

    /// Affine coordinates; `None` for infinity. Z's inversion is constant time.
    #[inline]
    pub(crate) fn to_affine(self) -> Option<Affine> {
        if self.is_infinity() {
            return None;
        }
        Some(self.scaled_by_inverse(&invert(&self.z, &MOD_P)))
    }

    #[inline(always)]
    fn scaled_by_inverse(&self, z_inv: &Limbs) -> Affine {
        let z_inv2 = fe_sqr(z_inv);
        Affine {
            x: fe_mul(&self.x, &z_inv2),
            y: fe_mul(&self.y, &fe_mul(&z_inv2, z_inv)),
        }
    }
}

/// Montgomery's trick: affine versions of `N` points that are not infinity, with one inversion.
pub(crate) fn normalize_batch<const N: usize>(points: &[Jacobian; N]) -> [Affine; N] {
    let mut products = [[0u64; 4]; N];
    let mut acc = ONE;
    for (product, point) in products.iter_mut().zip(points) {
        *product = acc;
        acc = fe_mul(&acc, &point.z);
    }
    let mut inv = invert(&acc, &MOD_P);
    let mut out = [Affine::ZERO; N];
    for i in (0..N).rev() {
        let z_inv = fe_mul(&inv, &products[i]);
        inv = fe_mul(&inv, &points[i].z);
        out[i] = points[i].scaled_by_inverse(&z_inv);
    }
    out
}
