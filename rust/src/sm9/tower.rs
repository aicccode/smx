//! Fq2 = Fq[u]/(u^2 + 2) and Fq4 = Fq2[v]/(v^2 - u), plus the `Field` trait the curve code uses.
//!
//! All operations are branch-free.

use super::fp::Fp;

/// What the generic Jacobian point code needs from its coordinate field.
pub(crate) trait Field: Copy {
    const ZERO: Self;
    const ONE: Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn dbl(&self) -> Self;
    fn neg(&self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn sqr(&self) -> Self;
    fn invert(&self) -> Self;
    /// All ones when zero.
    fn is_zero_mask(&self) -> u64;
    /// `a` where the mask is all ones, `b` where it is zero.
    fn select(mask: u64, a: &Self, b: &Self) -> Self;
}

impl Field for Fp {
    const ZERO: Fp = Fp::ZERO;
    const ONE: Fp = Fp::ONE;
    #[inline(always)]
    fn add(&self, other: &Self) -> Self {
        Fp::add(self, other)
    }
    #[inline(always)]
    fn sub(&self, other: &Self) -> Self {
        Fp::sub(self, other)
    }
    #[inline(always)]
    fn dbl(&self) -> Self {
        Fp::dbl(self)
    }
    #[inline(always)]
    fn neg(&self) -> Self {
        Fp::neg(self)
    }
    #[inline(always)]
    fn mul(&self, other: &Self) -> Self {
        Fp::mul(self, other)
    }
    #[inline(always)]
    fn sqr(&self) -> Self {
        Fp::sqr(self)
    }
    fn invert(&self) -> Self {
        Fp::invert(self)
    }
    #[inline(always)]
    fn is_zero_mask(&self) -> u64 {
        Fp::is_zero_mask(self)
    }
    #[inline(always)]
    fn select(mask: u64, a: &Self, b: &Self) -> Self {
        Fp::select(mask, a, b)
    }
}

/// c0 + c1 u
#[derive(Clone, Copy)]
pub(crate) struct Fp2 {
    pub(crate) c0: Fp,
    pub(crate) c1: Fp,
}

impl Fp2 {
    pub(crate) const fn new(c0: Fp, c1: Fp) -> Fp2 {
        Fp2 { c0, c1 }
    }

    /// From plain values (c0, c1); usable in constants.
    pub(crate) const fn from_raw(c0: [u64; 4], c1: [u64; 4]) -> Fp2 {
        Fp2::new(Fp::from_raw(c0), Fp::from_raw(c1))
    }

    /// x * u = -2 x1 + x0 u
    #[inline(always)]
    pub(crate) fn mul_u(&self) -> Fp2 {
        Fp2::new(self.c1.dbl().neg(), self.c0)
    }

    #[inline(always)]
    pub(crate) fn mul_fp(&self, k: &Fp) -> Fp2 {
        Fp2::new(self.c0.mul(k), self.c1.mul(k))
    }

    /// The q-power Frobenius: c0 - c1 u.
    #[inline(always)]
    pub(crate) fn conj(&self) -> Fp2 {
        Fp2::new(self.c0, self.c1.neg())
    }

    /// a1 || a0, 64 bytes.
    pub(crate) fn write_be(&self, out: &mut [u8]) {
        out[..32].copy_from_slice(&self.c1.to_be_bytes());
        out[32..64].copy_from_slice(&self.c0.to_be_bytes());
    }

    /// a1 || a0; `None` unless both are below q.
    pub(crate) fn from_be_bytes(bytes: &[u8]) -> Option<Fp2> {
        let c1 = Fp::from_be_bytes(&bytes[..32])?;
        let c0 = Fp::from_be_bytes(&bytes[32..64])?;
        Some(Fp2::new(c0, c1))
    }
}

impl Field for Fp2 {
    const ZERO: Fp2 = Fp2::new(Fp::ZERO, Fp::ZERO);
    const ONE: Fp2 = Fp2::new(Fp::ONE, Fp::ZERO);

    #[inline(always)]
    fn add(&self, o: &Self) -> Self {
        Fp2::new(self.c0.add(&o.c0), self.c1.add(&o.c1))
    }
    #[inline(always)]
    fn sub(&self, o: &Self) -> Self {
        Fp2::new(self.c0.sub(&o.c0), self.c1.sub(&o.c1))
    }
    #[inline(always)]
    fn dbl(&self) -> Self {
        Fp2::new(self.c0.dbl(), self.c1.dbl())
    }
    #[inline(always)]
    fn neg(&self) -> Self {
        Fp2::new(self.c0.neg(), self.c1.neg())
    }
    /// Karatsuba: three multiplications in Fq.
    #[inline(always)]
    fn mul(&self, o: &Self) -> Self {
        let t0 = self.c0.mul(&o.c0);
        let t1 = self.c1.mul(&o.c1);
        let cross = self.c0.add(&self.c1).mul(&o.c0.add(&o.c1));
        Fp2::new(t0.sub(&t1.dbl()), cross.sub(&t0).sub(&t1))
    }
    /// (a0 + a1 u)^2 = a0^2 - 2 a1^2 + 2 a0 a1 u, with two multiplications.
    #[inline(always)]
    fn sqr(&self) -> Self {
        let ab = self.c0.mul(&self.c1);
        let c0 = self
            .c0
            .sub(&self.c1)
            .mul(&self.c0.add(&self.c1.dbl()))
            .sub(&ab);
        Fp2::new(c0, ab.dbl())
    }
    /// (a0 - a1 u) / (a0^2 + 2 a1^2)
    fn invert(&self) -> Self {
        let norm = self.c0.sqr().add(&self.c1.sqr().dbl());
        let inv = norm.invert();
        Fp2::new(self.c0.mul(&inv), self.c1.mul(&inv).neg())
    }
    #[inline(always)]
    fn is_zero_mask(&self) -> u64 {
        self.c0.is_zero_mask() & self.c1.is_zero_mask()
    }
    #[inline(always)]
    fn select(mask: u64, a: &Self, b: &Self) -> Self {
        Fp2::new(
            Fp::select(mask, &a.c0, &b.c0),
            Fp::select(mask, &a.c1, &b.c1),
        )
    }
}

/// c0 + c1 v, v^2 = u
#[derive(Clone, Copy)]
pub(crate) struct Fp4 {
    pub(crate) c0: Fp2,
    pub(crate) c1: Fp2,
}

impl Fp4 {
    pub(crate) const ZERO: Fp4 = Fp4::new(Fp2::ZERO, Fp2::ZERO);
    pub(crate) const ONE: Fp4 = Fp4::new(Fp2::ONE, Fp2::ZERO);

    pub(crate) const fn new(c0: Fp2, c1: Fp2) -> Fp4 {
        Fp4 { c0, c1 }
    }

    #[inline(always)]
    pub(crate) fn add(&self, o: &Fp4) -> Fp4 {
        Fp4::new(self.c0.add(&o.c0), self.c1.add(&o.c1))
    }

    #[inline(always)]
    pub(crate) fn sub(&self, o: &Fp4) -> Fp4 {
        Fp4::new(self.c0.sub(&o.c0), self.c1.sub(&o.c1))
    }

    #[inline(always)]
    pub(crate) fn dbl(&self) -> Fp4 {
        Fp4::new(self.c0.dbl(), self.c1.dbl())
    }

    #[inline(always)]
    pub(crate) fn neg(&self) -> Fp4 {
        Fp4::new(self.c0.neg(), self.c1.neg())
    }

    /// Karatsuba: three multiplications in Fq2.
    #[inline(always)]
    pub(crate) fn mul(&self, o: &Fp4) -> Fp4 {
        let t0 = self.c0.mul(&o.c0);
        let t1 = self.c1.mul(&o.c1);
        let cross = self.c0.add(&self.c1).mul(&o.c0.add(&o.c1));
        Fp4::new(t0.add(&t1.mul_u()), cross.sub(&t0).sub(&t1))
    }

    /// Multiplication by an element of Fq2.
    #[inline(always)]
    pub(crate) fn mul_fp2(&self, k: &Fp2) -> Fp4 {
        Fp4::new(self.c0.mul(k), self.c1.mul(k))
    }

    /// (a0 + a1 v)^2 = a0^2 + a1^2 u + 2 a0 a1 v
    #[inline(always)]
    pub(crate) fn sqr(&self) -> Fp4 {
        let t0 = self.c0.sqr();
        let t1 = self.c1.sqr();
        let cross = self.c0.add(&self.c1).sqr().sub(&t0).sub(&t1);
        Fp4::new(t0.add(&t1.mul_u()), cross)
    }

    /// x * v = x1 u + x0 v
    #[inline(always)]
    pub(crate) fn mul_v(&self) -> Fp4 {
        Fp4::new(self.c1.mul_u(), self.c0)
    }

    /// v -> -v
    #[inline(always)]
    pub(crate) fn conj(&self) -> Fp4 {
        Fp4::new(self.c0, self.c1.neg())
    }

    /// (a0 - a1 v) / (a0^2 - a1^2 u)
    pub(crate) fn invert(&self) -> Fp4 {
        let norm = self.c0.sqr().sub(&self.c1.sqr().mul_u());
        let inv = norm.invert();
        Fp4::new(self.c0.mul(&inv), self.c1.mul(&inv).neg())
    }

    #[inline(always)]
    pub(crate) fn select(mask: u64, a: &Fp4, b: &Fp4) -> Fp4 {
        Fp4::new(
            Fp2::select(mask, &a.c0, &b.c0),
            Fp2::select(mask, &a.c1, &b.c1),
        )
    }
}
