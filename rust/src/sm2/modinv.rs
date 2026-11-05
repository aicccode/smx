//! Constant-time modular inversion with Bernstein-Yang "safegcd" divsteps, following the design
//! of libsecp256k1's `modinv64`: 590 divsteps in ten batches of 59, on signed 62-bit limbs.
//! The running time depends only on the modulus size, never on the value.

use super::field::{Limbs, ct_barrier};

const M62: u64 = u64::MAX >> 2;

#[derive(Clone, Copy)]
struct Signed62([i64; 5]);

/// A modulus in signed-62 form plus its inverse modulo 2^62.
pub(crate) struct Modulus {
    value: Signed62,
    inv62: u64,
}

impl Modulus {
    pub(crate) const fn new(m: &Limbs) -> Self {
        let mut inv = 1u64;
        let mut i = 0;
        while i < 6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
            i += 1;
        }
        Modulus {
            value: Signed62::from_limbs(m),
            inv62: inv & M62,
        }
    }
}

pub(crate) const MOD_P: Modulus = Modulus::new(&super::field::P);
pub(crate) const MOD_N: Modulus = Modulus::new(&super::order::N);

impl Signed62 {
    const fn from_limbs(a: &Limbs) -> Self {
        Signed62([
            (a[0] & M62) as i64,
            (((a[0] >> 62) | (a[1] << 2)) & M62) as i64,
            (((a[1] >> 60) | (a[2] << 4)) & M62) as i64,
            (((a[2] >> 58) | (a[3] << 6)) & M62) as i64,
            (a[3] >> 56) as i64,
        ])
    }

    /// Requires limbs normalized to [0, 2^62), as `normalize` leaves them.
    fn to_limbs(self) -> Limbs {
        let v = self.0.map(|x| x as u64);
        [
            v[0] | (v[1] << 62),
            (v[1] >> 2) | (v[2] << 60),
            (v[2] >> 4) | (v[3] << 58),
            (v[3] >> 6) | (v[4] << 56),
        ]
    }
}

/// 2x2 transition matrix, scaled by 2^62.
struct Matrix {
    u: i64,
    v: i64,
    q: i64,
    r: i64,
}

/// 59 divsteps on the low limbs of f and g, starting from `zeta`; returns the new zeta.
#[inline]
fn divsteps_59(mut zeta: i64, f0: u64, g0: u64) -> (i64, Matrix) {
    let (mut u, mut v, mut q, mut r) = (8u64, 0u64, 0u64, 8u64);
    let (mut f, mut g) = (f0, g0);
    for _ in 3..62 {
        let negative = ct_barrier((zeta >> 63) as u64);
        let odd = ct_barrier((g & 1).wrapping_neg());
        // Conditionally negated versions of f, u, v.
        let x = (f ^ negative).wrapping_sub(negative);
        let y = (u ^ negative).wrapping_sub(negative);
        let z = (v ^ negative).wrapping_sub(negative);
        // Add them to g, q, r when g is odd.
        g = g.wrapping_add(x & odd);
        q = q.wrapping_add(y & odd);
        r = r.wrapping_add(z & odd);
        let swap = negative & odd;
        zeta = (zeta ^ swap as i64).wrapping_sub(1);
        // Add the new g, q, r to f, u, v when swapping.
        f = f.wrapping_add(g & swap);
        u = u.wrapping_add(q & swap);
        v = v.wrapping_add(r & swap);
        g >>= 1;
        u = u.wrapping_shl(1);
        v = v.wrapping_shl(1);
    }
    (
        zeta,
        Matrix {
            u: u as i64,
            v: v as i64,
            q: q as i64,
            r: r as i64,
        },
    )
}

#[inline(always)]
const fn wide(a: i64, b: i64) -> i128 {
    a as i128 * b as i128
}

/// [d, e] = t * [d, e] / 2^62 modulo the modulus.
#[inline]
#[allow(clippy::needless_range_loop)] // the same index runs over three arrays
fn update_de(d: &mut Signed62, e: &mut Signed62, t: &Matrix, modulus: &Modulus) {
    let m = &modulus.value.0;
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);

    let sign_d = ct_barrier((d.0[4] >> 63) as u64) as i64;
    let sign_e = ct_barrier((e.0[4] >> 63) as u64) as i64;
    let mut md = (u & sign_d).wrapping_add(v & sign_e);
    let mut me = (q & sign_d).wrapping_add(r & sign_e);

    let mut cd = wide(u, d.0[0]) + wide(v, e.0[0]);
    let mut ce = wide(q, d.0[0]) + wide(r, e.0[0]);

    // Choose md, me so that the low 62 bits of t * [d, e] + modulus * [md, me] vanish.
    md = md.wrapping_sub(
        (modulus
            .inv62
            .wrapping_mul(cd as u64)
            .wrapping_add(md as u64)
            & M62) as i64,
    );
    me = me.wrapping_sub(
        (modulus
            .inv62
            .wrapping_mul(ce as u64)
            .wrapping_add(me as u64)
            & M62) as i64,
    );

    cd += wide(m[0], md);
    ce += wide(m[0], me);
    debug_assert!((cd as u64) & M62 == 0 && (ce as u64) & M62 == 0);
    cd >>= 62;
    ce >>= 62;

    for i in 1..5 {
        cd += wide(u, d.0[i]) + wide(v, e.0[i]) + wide(m[i], md);
        ce += wide(q, d.0[i]) + wide(r, e.0[i]) + wide(m[i], me);
        d.0[i - 1] = ((cd as u64) & M62) as i64;
        e.0[i - 1] = ((ce as u64) & M62) as i64;
        cd >>= 62;
        ce >>= 62;
    }
    d.0[4] = cd as i64;
    e.0[4] = ce as i64;
}

/// [f, g] = t * [f, g] / 2^62 as integers.
#[inline]
fn update_fg(f: &mut Signed62, g: &mut Signed62, t: &Matrix) {
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    let mut cf = wide(u, f.0[0]) + wide(v, g.0[0]);
    let mut cg = wide(q, f.0[0]) + wide(r, g.0[0]);
    debug_assert!((cf as u64) & M62 == 0 && (cg as u64) & M62 == 0);
    cf >>= 62;
    cg >>= 62;
    for i in 1..5 {
        cf += wide(u, f.0[i]) + wide(v, g.0[i]);
        cg += wide(q, f.0[i]) + wide(r, g.0[i]);
        f.0[i - 1] = ((cf as u64) & M62) as i64;
        g.0[i - 1] = ((cg as u64) & M62) as i64;
        cf >>= 62;
        cg >>= 62;
    }
    f.0[4] = cf as i64;
    g.0[4] = cg as i64;
}

#[inline(always)]
fn add_masked(x: &mut Signed62, modulus: &Signed62, mask: i64) {
    for (limb, m) in x.0.iter_mut().zip(modulus.0) {
        *limb = limb.wrapping_add(m & mask);
    }
}

#[inline(always)]
fn propagate(x: &mut Signed62) {
    let v = &mut x.0;
    v[1] += v[0] >> 62;
    v[0] &= M62 as i64;
    v[2] += v[1] >> 62;
    v[1] &= M62 as i64;
    v[3] += v[2] >> 62;
    v[2] &= M62 as i64;
    v[4] += v[3] >> 62;
    v[3] &= M62 as i64;
}

/// Brings d from (-2 * modulus, modulus) into [0, modulus), negated when `sign` is negative.
#[inline]
fn normalize(d: &mut Signed62, sign: i64, modulus: &Signed62) {
    add_masked(d, modulus, ct_barrier((d.0[4] >> 63) as u64) as i64);
    let negate = ct_barrier((sign >> 63) as u64) as i64;
    for limb in &mut d.0 {
        *limb = (*limb ^ negate).wrapping_sub(negate);
    }
    propagate(d);
    add_masked(d, modulus, ct_barrier((d.0[4] >> 63) as u64) as i64);
    propagate(d);
}

/// a^-1 modulo an odd modulus, for a in [0, modulus); zero maps to zero.
pub(crate) fn invert(a: &Limbs, modulus: &Modulus) -> Limbs {
    let mut d = Signed62([0; 5]);
    let mut e = Signed62([1, 0, 0, 0, 0]);
    let mut f = modulus.value;
    let mut g = Signed62::from_limbs(a);
    let mut zeta = -1i64;
    for _ in 0..10 {
        let (next_zeta, t) = divsteps_59(zeta, f.0[0] as u64, g.0[0] as u64);
        zeta = next_zeta;
        update_de(&mut d, &mut e, &t, modulus);
        update_fg(&mut f, &mut g, &t);
    }
    normalize(&mut d, f.0[4], &modulus.value);
    d.to_limbs()
}
