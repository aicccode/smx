//! The R-ate pairing e: G1 x G2 -> GT with a = 6t + 2 (GB/T 38635.1, B.6.2).
//!
//! Projective Miller loop: T stays in Jacobian coordinates on the twist and each line is
//! evaluated at P without inversions. Through the untwisting map a line through T with slope
//! lambda, multiplied by w^3, is (y_T - lambda x_T) + (lambda x_P) w^2 - y_P w^3; the projective
//! formulas give it times a factor in Fq2, which the final exponentiation removes, as it removes
//! the vertical lines that are left out.
//!
//! Only public loop bits are branched on. The points can be secret (a user's private key), and
//! the field arithmetic is branch-free, so the pairing is constant time in its inputs.

use super::curve::{G1Affine, G2, G2Affine};
use super::fp::Fp;
use super::fp12::Fp12;
use super::tower::{Field, Fp2, Fp4};

/// 6t + 2
const LOOP: u128 = 6 * T as u128 + 2;
/// The BN parameter t.
const T: u64 = 0x6000_0000_0058_f98a;

/// A line as the Fq4 part (w^0 and w^3 coefficients) and the w^2 coefficient.
struct Line {
    b0: Fp4,
    l2: Fp2,
}

/// T = 2T, and the tangent at the old T evaluated at P (scaled by 2 Y Z^3).
fn double_step(t: &mut G2, xp: &Fp, neg_yp: &Fp) -> Line {
    let a = t.x.sqr();
    let b = t.y.sqr();
    let c = b.sqr();
    let d = t.x.add(&b).sqr().sub(&a).sub(&c).dbl();
    let e = a.dbl().add(&a);
    let zz = t.z.sqr();
    let x3 = e.sqr().sub(&d.dbl());
    let y3 = e.mul(&d.sub(&x3)).sub(&c.dbl().dbl().dbl());
    let z3 = t.y.mul(&t.z).dbl();

    let l0 = b.dbl().sub(&e.mul(&t.x));
    let l3 = z3.mul(&zz).mul_fp(neg_yp);
    let l2 = e.mul(&zz).mul_fp(xp);
    *t = G2 {
        x: x3,
        y: y3,
        z: z3,
    };
    Line {
        b0: Fp4::new(l0, l3),
        l2,
    }
}

/// T = T + Q, and the line through T and Q evaluated at P (scaled by Z H). When T = -Q this is
/// the vertical line times a factor, an element of Fq6 that the final exponentiation removes.
fn add_step(t: &mut G2, q: &G2Affine, xp: &Fp, neg_yp: &Fp) -> Line {
    let zz = t.z.sqr();
    let h = q.x.mul(&zz).sub(&t.x);
    let r = q.y.mul(&t.z).mul(&zz).sub(&t.y);
    let hh = h.sqr();
    let hhh = h.mul(&hh);
    let v = t.x.mul(&hh);
    let x3 = r.sqr().sub(&hhh).sub(&v.dbl());
    let y3 = r.mul(&v.sub(&x3)).sub(&t.y.mul(&hhh));
    let z3 = t.z.mul(&h);

    let l0 = q.y.mul(&z3).sub(&r.mul(&q.x));
    let l3 = z3.mul_fp(neg_yp);
    let l2 = r.mul_fp(xp);
    *t = G2 {
        x: x3,
        y: y3,
        z: z3,
    };
    Line {
        b0: Fp4::new(l0, l3),
        l2,
    }
}

/// The product of the Miller loop values of all pairs, sharing the squarings of f. At most
/// `MAX_PAIRS` pairs.
fn miller_loop(pairs: &[(&G1Affine, &G2Affine)]) -> Fp12 {
    debug_assert!(pairs.len() <= MAX_PAIRS);
    let mut xp = [Fp::ZERO; MAX_PAIRS];
    let mut neg_yp = [Fp::ZERO; MAX_PAIRS];
    let mut t = [G2::INFINITY; MAX_PAIRS];
    for (i, (p, q)) in pairs.iter().enumerate() {
        xp[i] = p.x;
        neg_yp[i] = p.y.neg();
        t[i] = q.to_jacobian();
    }
    let n = pairs.len();
    let mut f = Fp12::ONE;
    for bit in (0..(127 - LOOP.leading_zeros())).rev() {
        f = f.sqr();
        for i in 0..n {
            let line = double_step(&mut t[i], &xp[i], &neg_yp[i]);
            f = f.mul_by_line(&line.b0, &line.l2);
        }
        if (LOOP >> bit) & 1 == 1 {
            for (i, (_, q)) in pairs.iter().enumerate() {
                let line = add_step(&mut t[i], q, &xp[i], &neg_yp[i]);
                f = f.mul_by_line(&line.b0, &line.l2);
            }
        }
    }
    for (i, (_, q)) in pairs.iter().enumerate() {
        let q1 = q.frobenius();
        let q2 = q1.frobenius().neg();
        let line = add_step(&mut t[i], &q1, &xp[i], &neg_yp[i]);
        f = f.mul_by_line(&line.b0, &line.l2);
        let line = add_step(&mut t[i], &q2, &xp[i], &neg_yp[i]);
        f = f.mul_by_line(&line.b0, &line.l2);
    }
    f
}

/// Pairs one multi-pairing takes.
const MAX_PAIRS: usize = 2;

/// e(P, Q) for valid affine points (never the identity: they cannot be represented).
pub(crate) fn pairing(p: &G1Affine, q: &G2Affine) -> Fp12 {
    miller_loop(&[(p, q)]).final_exponentiation()
}

/// e(P1, Q1) e(P2, Q2) with one final exponentiation.
pub(crate) fn pairing_product(a: (&G1Affine, &G2Affine), b: (&G1Affine, &G2Affine)) -> Fp12 {
    miller_loop(&[a, b]).final_exponentiation()
}

#[cfg(test)]
mod tests {
    use super::super::curve::{P1, P2};
    use super::super::fp::N;
    use super::*;

    #[test]
    fn pairing_is_bilinear_and_of_order_n() {
        let g = pairing(&P1, &P2);
        assert!(!g.eq_vartime(&Fp12::ONE));
        assert!(g.pow_ct(&N).eq_vartime(&Fp12::ONE));
        let k = [0x1234_5678, 0x9abc, 0xdef0, 0x1111];
        let pk = P1.to_jacobian().mul_ct(&k).to_affine().unwrap();
        let qk = P2.to_jacobian().mul_ct(&k).to_affine().unwrap();
        let gk = g.pow_ct(&k);
        assert!(pairing(&pk, &P2).eq_vartime(&gk));
        assert!(pairing(&P1, &qk).eq_vartime(&gk));
        let product = pairing_product((&pk, &P2), (&P1, &qk));
        assert!(product.eq_vartime(&gk.mul(&gk)));
        // Cyclotomic squaring agrees with the general one in GT.
        assert!(g.sqr().eq_vartime(&g.cyclotomic_sqr()));
    }
}
