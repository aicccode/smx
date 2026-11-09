//! G1 on E: y^2 = x^3 + 5 over Fq and G2 on the twist E': y^2 = x^3 + 5u over Fq2, both in
//! Jacobian coordinates (x = X/Z^2, y = Y/Z^3) through one generic implementation.
//!
//! `mul_ct` is for secret scalars: signed fixed windows, a masked scan of the whole table and
//! complete, branch-free additions. `mul_vartime` and `add_vartime` are for public data only.

use super::fp::{Fp, Limbs};
use super::fp12::{booth_digit, eq_mask};
use super::tower::{Field, Fp2};

/// Width of the signed windows of the scalar multiplications.
const WIDTH: usize = 5;
const WINDOWS: usize = 256 / WIDTH + 1;
const ENTRIES: usize = 1 << (WIDTH - 1);

/// An affine point, never the identity.
#[derive(Clone, Copy)]
pub(crate) struct Affine<F> {
    pub(crate) x: F,
    pub(crate) y: F,
}

/// Z = 0 is the identity.
#[derive(Clone, Copy)]
pub(crate) struct Jacobian<F> {
    pub(crate) x: F,
    pub(crate) y: F,
    pub(crate) z: F,
}

pub(crate) type G1Affine = Affine<Fp>;
pub(crate) type G2Affine = Affine<Fp2>;
pub(crate) type G1 = Jacobian<Fp>;
pub(crate) type G2 = Jacobian<Fp2>;

pub(crate) const G1_B: Fp = Fp::from_raw([5, 0, 0, 0]);
pub(crate) const G2_B: Fp2 = Fp2::from_raw([0; 4], [5, 0, 0, 0]);

/// The generator P1 of G1.
pub(crate) const P1: G1Affine = Affine {
    x: Fp::from_raw([
        0xe8c4e4817c66dddd,
        0xe1e4086909dc3280,
        0xf5ed0704487d01d6,
        0x93de051d62bf718f,
    ]),
    y: Fp::from_raw([
        0x0c464cd70a3ea616,
        0x1c1c00cbfa602435,
        0x631065125c395bbc,
        0x21fe8dda4f21e607,
    ]),
};

/// The generator P2 of G2.
pub(crate) const P2: G2Affine = Affine {
    x: Fp2::from_raw(
        [
            0xf9b7213baf82d65b,
            0xee265948d19c17ab,
            0xd2aab97fd34ec120,
            0x3722755292130b08,
        ],
        [
            0x54806c11d8806141,
            0xf1dd2c190f5e93c4,
            0x597b6027b441a01f,
            0x85aef3d078640c98,
        ],
    ),
    y: Fp2::from_raw(
        [
            0x6215bba5c999a7c7,
            0x47efba98a71a0811,
            0x5f3170153d278ff2,
            0xa7cf28d519be3da6,
        ],
        [
            0x856dc76b84ebeb96,
            0x0736a96fa347c8bd,
            0x66ba0d262cbee6ed,
            0x17509b092e845c12,
        ],
    ),
};

/// Frobenius on the twist: pi(x, y) = (conj(x) PI_X, conj(y) PI_Y); both constants lie in Fq.
const PI_X: Fp = Fp::from_raw([
    0x0f738991676af24a,
    0xa9f02115caef75e7,
    0xe303ab4ff2eb2052,
    0xb640000002a3a6f0,
]);
const PI_Y: Fp = Fp::from_raw([
    0xefbd7b54092c756c,
    0x82555233139e9d63,
    0xe0a8debc0783182f,
    0x49db721a269967c4,
]);

impl<F: Field> Affine<F> {
    /// y^2 == x^3 + b
    pub(crate) fn is_on_curve(&self, b: &F) -> bool {
        let rhs = self.x.sqr().mul(&self.x).add(b);
        self.y.sqr().sub(&rhs).is_zero_mask() != 0
    }

    pub(crate) fn to_jacobian(self) -> Jacobian<F> {
        Jacobian {
            x: self.x,
            y: self.y,
            z: F::ONE,
        }
    }

    pub(crate) fn neg(&self) -> Affine<F> {
        Affine {
            x: self.x,
            y: self.y.neg(),
        }
    }
}

impl G2Affine {
    pub(crate) fn frobenius(&self) -> G2Affine {
        Affine {
            x: self.x.conj().mul_fp(&PI_X),
            y: self.y.conj().mul_fp(&PI_Y),
        }
    }
}

impl<F: Field> Jacobian<F> {
    pub(crate) const INFINITY: Jacobian<F> = Jacobian {
        x: F::ONE,
        y: F::ONE,
        z: F::ZERO,
    };

    pub(crate) fn is_infinity(&self) -> bool {
        self.z.is_zero_mask() != 0
    }

    fn select(mask: u64, a: &Self, b: &Self) -> Self {
        Jacobian {
            x: F::select(mask, &a.x, &b.x),
            y: F::select(mask, &a.y, &b.y),
            z: F::select(mask, &a.z, &b.z),
        }
    }

    /// dbl-2009-l for a = 0; the identity stays the identity.
    pub(crate) fn double(&self) -> Self {
        let a = self.x.sqr();
        let b = self.y.sqr();
        let c = b.sqr();
        let d = self.x.add(&b).sqr().sub(&a).sub(&c).dbl();
        let e = a.dbl().add(&a);
        let f = e.sqr();
        let x3 = f.sub(&d.dbl());
        let y3 = e.mul(&d.sub(&x3)).sub(&c.dbl().dbl().dbl());
        let z3 = self.y.mul(&self.z).dbl();
        Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// add-2007-bl without the exceptional cases; also returns the masks for H = 0 and r = 0.
    fn add_raw(&self, o: &Self) -> (Self, u64, u64) {
        let z1z1 = self.z.sqr();
        let z2z2 = o.z.sqr();
        let u1 = self.x.mul(&z2z2);
        let u2 = o.x.mul(&z1z1);
        let s1 = self.y.mul(&o.z).mul(&z2z2);
        let s2 = o.y.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&u1);
        let i = h.dbl().sqr();
        let j = h.mul(&i);
        let r = s2.sub(&s1).dbl();
        let v = u1.mul(&i);
        let x3 = r.sqr().sub(&j).sub(&v.dbl());
        let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&j).dbl());
        let z3 = self.z.add(&o.z).sqr().sub(&z1z1).sub(&z2z2).mul(&h);
        let sum = Jacobian {
            x: x3,
            y: y3,
            z: z3,
        };
        (sum, h.is_zero_mask(), r.is_zero_mask())
    }

    /// Complete addition without branches: identities, doubling and P + (-P) handled by masks.
    pub(crate) fn add(&self, o: &Self) -> Self {
        let (sum, h_zero, r_zero) = self.add_raw(o);
        let doubled = self.double();
        let sum = Self::select(h_zero & r_zero, &doubled, &sum);
        let sum = Self::select(o.z.is_zero_mask(), self, &sum);
        Self::select(self.z.is_zero_mask(), o, &sum)
    }

    /// Complete addition for public points.
    pub(crate) fn add_vartime(&self, o: &Self) -> Self {
        if self.is_infinity() {
            return *o;
        }
        if o.is_infinity() {
            return *self;
        }
        let (sum, h_zero, r_zero) = self.add_raw(o);
        if h_zero != 0 && r_zero != 0 {
            return self.double();
        }
        sum
    }

    pub(crate) fn neg(&self) -> Self {
        Jacobian {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// The affine point, or `None` for the identity.
    pub(crate) fn to_affine(self) -> Option<Affine<F>> {
        if self.is_infinity() {
            return None;
        }
        let zi = self.z.invert();
        let zi2 = zi.sqr();
        Some(Affine {
            x: self.x.mul(&zi2),
            y: self.y.mul(&zi2).mul(&zi),
        })
    }

    /// 1P .. 16P; built with complete additions, so constant time for a secret point too.
    fn table(&self) -> [Self; ENTRIES] {
        let mut table = [*self; ENTRIES];
        for i in 1..ENTRIES {
            table[i] = if i % 2 == 1 {
                table[i / 2].double()
            } else {
                table[i - 1].add(self)
            };
        }
        table
    }

    /// [k]P for any 256-bit k with a regular schedule; P may be secret.
    pub(crate) fn mul_ct(&self, k: &Limbs) -> Self {
        let table = self.table();
        let mut acc = Self::INFINITY;
        for index in (0..WINDOWS).rev() {
            if index != WINDOWS - 1 {
                for _ in 0..WIDTH {
                    acc = acc.double();
                }
            }
            let (magnitude, negative) = booth_digit(k, index, WIDTH as u32);
            let mut entry = Self::INFINITY;
            for (i, candidate) in table.iter().enumerate() {
                entry = Self::select(eq_mask(i as u64 + 1, magnitude), candidate, &entry);
            }
            entry.y = F::select(negative, &entry.y.neg(), &entry.y);
            acc = acc.add(&entry);
        }
        acc
    }

    /// [k]P for public k and P.
    pub(crate) fn mul_vartime(&self, k: &Limbs) -> Self {
        let mut table = [*self; ENTRIES];
        for i in 1..ENTRIES {
            table[i] = table[i - 1].add_vartime(self);
        }
        let mut acc = Self::INFINITY;
        for index in (0..WINDOWS).rev() {
            if !acc.is_infinity() {
                for _ in 0..WIDTH {
                    acc = acc.double();
                }
            }
            let (magnitude, negative) = booth_digit(k, index, WIDTH as u32);
            if magnitude != 0 {
                let entry = table[magnitude as usize - 1];
                let entry = if negative != 0 { entry.neg() } else { entry };
                acc = acc.add_vartime(&entry);
            }
        }
        acc
    }
}

/// 04 || x || y, 65 bytes.
pub(crate) fn g1_encode(p: &G1Affine) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[0] = 4;
    out[1..33].copy_from_slice(&p.x.to_be_bytes());
    out[33..].copy_from_slice(&p.y.to_be_bytes());
    out
}

/// A valid G1 point from 04 || x || y. G1 has cofactor 1, so on the curve means in G1.
pub(crate) fn g1_decode(bytes: &[u8]) -> Option<G1Affine> {
    if bytes.len() != 65 || bytes[0] != 4 {
        return None;
    }
    let p = Affine {
        x: Fp::from_be_bytes(&bytes[1..33])?,
        y: Fp::from_be_bytes(&bytes[33..65])?,
    };
    p.is_on_curve(&G1_B).then_some(p)
}

/// 04 || x1 || x0 || y1 || y0, 129 bytes.
pub(crate) fn g2_encode(p: &G2Affine) -> [u8; 129] {
    let mut out = [0u8; 129];
    out[0] = 4;
    p.x.write_be(&mut out[1..65]);
    p.y.write_be(&mut out[65..]);
    out
}

/// A valid G2 point: on the twist, coordinates below q, and in the order-N subgroup.
pub(crate) fn g2_decode(bytes: &[u8]) -> Option<G2Affine> {
    if bytes.len() != 129 || bytes[0] != 4 {
        return None;
    }
    let p = Affine {
        x: Fp2::from_be_bytes(&bytes[1..65])?,
        y: Fp2::from_be_bytes(&bytes[65..129])?,
    };
    if !p.is_on_curve(&G2_B) {
        return None;
    }
    // The twist has a cofactor, so check the subgroup. Public data: variable time is fine.
    is_in_g2(&p).then_some(p)
}

/// 6t^2 = q mod N, the eigenvalue of the twisted Frobenius psi on G2.
const SIX_T_SQUARED: Limbs = [0x0000b98b0cb27658, 0xd8000000019062ed, 0, 0];

/// Q in G2 iff psi(Q) = [6t^2]Q. Exact, and half the work of [N]Q = O: psi satisfies
/// X^2 - (6t^2 + 1) X + q = 0, so psi - [6t^2] has degree 36t^4 - (6t^2 + 1) 6t^2 + q = N, and its
/// kernel, which contains G2, has exactly N points.
fn is_in_g2(p: &G2Affine) -> bool {
    let lhs = p.frobenius();
    let rhs = p.to_jacobian().mul_vartime(&SIX_T_SQUARED);
    if rhs.is_infinity() {
        return false;
    }
    // Compare (x, y) with (X / Z^2, Y / Z^3) without inverting.
    let z2 = rhs.z.sqr();
    let x_diff = lhs.x.mul(&z2).sub(&rhs.x);
    let y_diff = lhs.y.mul(&z2).mul(&rhs.z).sub(&rhs.y);
    (x_diff.is_zero_mask() & y_diff.is_zero_mask()) != 0
}

#[cfg(test)]
mod tests {
    use super::super::fp::N;
    use super::*;

    #[test]
    fn generators_are_valid_and_of_order_n() {
        assert!(P1.is_on_curve(&G1_B));
        assert!(P2.is_on_curve(&G2_B));
        assert!(P1.to_jacobian().mul_vartime(&N).is_infinity());
        assert!(P1.to_jacobian().mul_ct(&N).is_infinity());
        assert!(P2.to_jacobian().mul_ct(&N).is_infinity());
        assert!(g2_decode(&g2_encode(&P2)).is_some());
        assert!(g1_decode(&g1_encode(&P1)).is_some());
    }

    /// A twist point outside G2 (the `not_in_subgroup` vector: x = 1 + u).
    const NOT_IN_SUBGROUP: &str = "04\
        0000000000000000000000000000000000000000000000000000000000000001\
        0000000000000000000000000000000000000000000000000000000000000001\
        231bf6749ac68a2223472afbd4341831d08572cf445ea350acf8d3b903d69b91\
        1ebd2e84018fa77c3fc8399d45d9dc3c87862881cc21539326f6e078a8f3e5e7";

    /// The fast subgroup test against the definition [N]Q = O, on G2 points and on sums of
    /// G2 points with multiples of a point outside G2.
    #[test]
    fn subgroup_test_matches_the_definition() {
        let in_g2 = P2
            .to_jacobian()
            .mul_vartime(&[7, 0, 0, 1])
            .to_affine()
            .unwrap();
        assert!(is_in_g2(&P2) && is_in_g2(&in_g2));
        let not_in_g2 = crate::hex::decode_plain(NOT_IN_SUBGROUP).unwrap();
        let p = Affine {
            x: Fp2::from_be_bytes(&not_in_g2[1..65]).unwrap(),
            y: Fp2::from_be_bytes(&not_in_g2[65..129]).unwrap(),
        };
        assert!(p.is_on_curve(&G2_B));
        for k in 1..20u64 {
            let q = p
                .to_jacobian()
                .mul_vartime(&[k, 0, 0, 0])
                .add_vartime(&in_g2.to_jacobian());
            let q = q.to_affine().unwrap();
            let by_order = q.to_jacobian().mul_vartime(&N).is_infinity();
            assert_eq!(is_in_g2(&q), by_order, "{k}");
        }
        assert!(!is_in_g2(&p));
    }

    #[test]
    fn ct_and_vartime_multiplication_agree() {
        let k = [
            0x1234_5678_9abc_def0,
            0x0fed_cba9_8765_4321,
            7,
            0x8000_0000_0000_0001,
        ];
        let a = P1.to_jacobian().mul_ct(&k).to_affine().unwrap();
        let b = P1.to_jacobian().mul_vartime(&k).to_affine().unwrap();
        assert_eq!(g1_encode(&a), g1_encode(&b));
        let a = P2.to_jacobian().mul_ct(&k).to_affine().unwrap();
        let b = P2.to_jacobian().mul_vartime(&k).to_affine().unwrap();
        assert_eq!(g2_encode(&a), g2_encode(&b));
        // N - 1 gives -P, exercising the doubling and cancelling cases near the end.
        let mut n1 = N;
        n1[0] -= 1;
        let neg = P1.to_jacobian().mul_ct(&n1).to_affine().unwrap();
        assert_eq!(g1_encode(&neg), g1_encode(&P1.neg()));
    }
}
