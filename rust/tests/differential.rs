//! Randomized differential tests of the public arithmetic against a deliberately simple reference:
//! bit-by-bit modular reduction and textbook Jacobian formulas, sharing no code with the crate.
//! The random generator is seeded, so failures reproduce.

#![allow(clippy::needless_range_loop)] // reference code favours plain limb indexing

use gm_rust::sm2::bigint256::BigInt256;
use gm_rust::sm2::fp::{FpElement, SM2_P};
use gm_rust::sm2::point::{ECPoint, SM2_B, SM2_GX, SM2_GY, SM2_N};
use std::cmp::Ordering;

// ---------------------------------------------------------------- reference big integers

type U256 = [u64; 4];

fn sub_u(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut out = Vec::with_capacity(a.len());
    let mut borrow = 0u128;
    for i in 0..a.len() {
        let d = (a[i] as u128)
            .wrapping_sub(*b.get(i).unwrap_or(&0) as u128)
            .wrapping_sub(borrow);
        out.push(d as u64);
        borrow = (d >> 64) & 1;
    }
    out
}

fn ge_u(a: &[u64], b: &[u64]) -> bool {
    for i in (0..a.len().max(b.len())).rev() {
        let (x, y) = (*a.get(i).unwrap_or(&0), *b.get(i).unwrap_or(&0));
        if x != y {
            return x > y;
        }
    }
    true
}

/// Binary long division remainder of a little-endian integer.
fn rem(value: &[u64], m: &U256) -> U256 {
    let mut r = vec![0u64; 5];
    for i in (0..value.len() * 64).rev() {
        let mut carry = (value[i / 64] >> (i % 64)) & 1;
        for limb in r.iter_mut() {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        if ge_u(&r, m) {
            r = sub_u(&r, m);
        }
    }
    [r[0], r[1], r[2], r[3]]
}

fn wide_mul(a: &U256, b: &U256) -> [u64; 8] {
    let mut out = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = out[i + j] as u128 + a[i] as u128 * b[j] as u128 + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
        out[i + 4] = carry as u64;
    }
    out
}

fn mul_m(a: &U256, b: &U256, m: &U256) -> U256 {
    rem(&wide_mul(a, b), m)
}

fn add_m(a: &U256, b: &U256, m: &U256) -> U256 {
    let mut sum = [0u64; 5];
    let mut carry = 0u128;
    for i in 0..4 {
        let t = a[i] as u128 + b[i] as u128 + carry;
        sum[i] = t as u64;
        carry = t >> 64;
    }
    sum[4] = carry as u64;
    rem(&sum, m)
}

fn sub_m(a: &U256, b: &U256, m: &U256) -> U256 {
    let a = rem(a, m);
    let b = rem(b, m);
    if ge_u(&a, &b) {
        let d = sub_u(&a, &b);
        [d[0], d[1], d[2], d[3]]
    } else {
        let d = sub_u(m, &sub_u(&b, &a));
        [d[0], d[1], d[2], d[3]]
    }
}

// ---------------------------------------------------------------- reference curve

const P: U256 = SM2_P.limbs;

fn fmul(a: &U256, b: &U256) -> U256 {
    mul_m(a, b, &P)
}
fn fadd(a: &U256, b: &U256) -> U256 {
    add_m(a, b, &P)
}
fn fsub(a: &U256, b: &U256) -> U256 {
    sub_m(a, b, &P)
}
fn fpow(a: &U256, e: &U256) -> U256 {
    let mut r = [1, 0, 0, 0];
    for i in (0..256).rev() {
        r = fmul(&r, &r);
        if (e[i / 64] >> (i % 64)) & 1 == 1 {
            r = fmul(&r, a);
        }
    }
    r
}
fn finv(a: &U256) -> U256 {
    let mut e = P;
    e[0] -= 2;
    fpow(a, &e)
}

#[derive(Clone, Copy)]
struct RefPoint {
    x: U256,
    y: U256,
    z: U256,
}

const ZERO: U256 = [0; 4];
const ONE: U256 = [1, 0, 0, 0];
const REF_INF: RefPoint = RefPoint {
    x: ONE,
    y: ONE,
    z: ZERO,
};

/// General a = -3 doubling: M = 3X^2 + aZ^4 and the classic textbook formulas.
fn ref_double(p: &RefPoint) -> RefPoint {
    if p.z == ZERO || p.y == ZERO {
        return REF_INF;
    }
    let yy = fmul(&p.y, &p.y);
    let s = {
        let t = fmul(&p.x, &yy);
        fadd(&fadd(&t, &t), &fadd(&t, &t))
    };
    let zz = fmul(&p.z, &p.z);
    let xx = fmul(&p.x, &p.x);
    let m = fsub(
        &fadd(&fadd(&xx, &xx), &xx),
        &fadd(&fadd(&fmul(&zz, &zz), &fmul(&zz, &zz)), &fmul(&zz, &zz)),
    );
    let x3 = fsub(&fmul(&m, &m), &fadd(&s, &s));
    let yyyy = fmul(&yy, &yy);
    let eight = fadd(
        &fadd(&fadd(&yyyy, &yyyy), &fadd(&yyyy, &yyyy)),
        &fadd(&fadd(&yyyy, &yyyy), &fadd(&yyyy, &yyyy)),
    );
    let y3 = fsub(&fmul(&m, &fsub(&s, &x3)), &eight);
    let z3 = {
        let t = fmul(&p.y, &p.z);
        fadd(&t, &t)
    };
    RefPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn ref_add(p: &RefPoint, q: &RefPoint) -> RefPoint {
    if p.z == ZERO {
        return *q;
    }
    if q.z == ZERO {
        return *p;
    }
    let z1z1 = fmul(&p.z, &p.z);
    let z2z2 = fmul(&q.z, &q.z);
    let u1 = fmul(&p.x, &z2z2);
    let u2 = fmul(&q.x, &z1z1);
    let s1 = fmul(&p.y, &fmul(&q.z, &z2z2));
    let s2 = fmul(&q.y, &fmul(&p.z, &z1z1));
    let h = fsub(&u2, &u1);
    let r = fsub(&s2, &s1);
    if h == ZERO {
        return if r == ZERO { ref_double(p) } else { REF_INF };
    }
    let hh = fmul(&h, &h);
    let hhh = fmul(&hh, &h);
    let v = fmul(&u1, &hh);
    let x3 = fsub(&fsub(&fmul(&r, &r), &hhh), &fadd(&v, &v));
    let y3 = fsub(&fmul(&r, &fsub(&v, &x3)), &fmul(&s1, &hhh));
    let z3 = fmul(&fmul(&p.z, &q.z), &h);
    RefPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn ref_mul(p: &RefPoint, k: &U256) -> RefPoint {
    let mut acc = REF_INF;
    for i in (0..256).rev() {
        acc = ref_double(&acc);
        if (k[i / 64] >> (i % 64)) & 1 == 1 {
            acc = ref_add(&acc, p);
        }
    }
    acc
}

fn ref_affine(p: &RefPoint) -> Option<(U256, U256)> {
    if p.z == ZERO {
        return None;
    }
    let zi = finv(&p.z);
    let zi2 = fmul(&zi, &zi);
    Some((fmul(&p.x, &zi2), fmul(&p.y, &fmul(&zi2, &zi))))
}

fn assert_same(actual: &ECPoint, expected: &RefPoint, what: &str) {
    match ref_affine(expected) {
        None => assert!(actual.is_infinity(), "{what}: expected infinity"),
        Some((x, y)) => {
            assert!(!actual.is_infinity(), "{what}: unexpected infinity");
            assert_eq!(actual.x.value.limbs, x, "{what}: x");
            assert_eq!(actual.y.value.limbs, y, "{what}: y");
        }
    }
}

fn to_ref(p: &ECPoint) -> RefPoint {
    if p.is_infinity() {
        return REF_INF;
    }
    RefPoint {
        x: p.x.value.limbs,
        y: p.y.value.limbs,
        z: ONE,
    }
}

fn fp(limbs: U256) -> FpElement {
    FpElement::new(BigInt256::new(limbs))
}

// ---------------------------------------------------------------- inputs

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // SplitMix64
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn u256(&mut self) -> U256 {
        [self.next(), self.next(), self.next(), self.next()]
    }

    /// Mostly uniform values, with patterns of saturated and empty limbs that force carries.
    fn interesting(&mut self) -> U256 {
        let mut v = self.u256();
        match self.next() % 4 {
            0 => {
                for limb in v.iter_mut() {
                    match self.next() % 4 {
                        0 => *limb = 0,
                        1 => *limb = u64::MAX,
                        2 => *limb = 0xFFFF_FFFF,
                        _ => *limb = 0xFFFF_FFFF_0000_0000,
                    }
                }
            }
            1 => {
                let shift = self.next() % 64;
                v[(self.next() % 4) as usize] = 1u64 << shift;
            }
            _ => {}
        }
        v
    }
}

fn minus(a: &U256, small: u64) -> U256 {
    let d = sub_u(a, &[small]);
    [d[0], d[1], d[2], d[3]]
}

fn plus(a: &U256, small: u64) -> U256 {
    let (mut out, mut carry) = (*a, small);
    for limb in out.iter_mut() {
        let (v, c) = limb.overflowing_add(carry);
        *limb = v;
        carry = c as u64;
    }
    out
}

const MAX: U256 = [u64::MAX; 4];

fn field_edges() -> Vec<U256> {
    let n = SM2_N.limbs;
    vec![
        ZERO,
        ONE,
        [2, 0, 0, 0],
        minus(&P, 1),
        minus(&P, 2),
        P,
        plus(&P, 1),
        minus(&n, 1),
        n,
        plus(&n, 1),
        MAX,
        minus(&MAX, 1),
        [0, 0, 0, 1 << 63],
        [u64::MAX, u64::MAX, u64::MAX, 0],
        [0, 0, 0, u64::MAX],
        [0xFFFF_FFFF, 0, 0, 0],
        [0, 0xFFFF_FFFF_0000_0000, 0, 0],
        [0, 0, 0, 0xFFFF_FFFF],
    ]
}

fn value_pairs(iterations: usize, seed: u64) -> Vec<(U256, U256)> {
    let mut pairs = Vec::new();
    let edges = field_edges();
    for a in &edges {
        for b in &edges {
            pairs.push((*a, *b));
        }
    }
    let mut rng = Rng(seed);
    for _ in 0..iterations {
        pairs.push((rng.interesting(), rng.interesting()));
    }
    pairs
}

// ---------------------------------------------------------------- tests: integers

#[test]
fn modular_multiplication_for_sm2_moduli() {
    for (a, b) in value_pairs(4000, 1) {
        let (x, y) = (BigInt256::new(a), BigInt256::new(b));
        let expected_p = mul_m(&a, &b, &P);
        assert_eq!(x.sm2_mod_mul_p(&y).limbs, expected_p, "{a:x?} {b:x?}");
        assert_eq!(x.mod_mul(&y, &SM2_P).limbs, expected_p);
        assert_eq!(x.sm2_mod_square_p().limbs, mul_m(&a, &a, &P));
        assert_eq!(x.mod_square(&SM2_P).limbs, mul_m(&a, &a, &P));
        assert_eq!(
            x.mod_mul(&y, &SM2_N).limbs,
            mul_m(&a, &b, &SM2_N.limbs),
            "{a:x?} {b:x?}"
        );
        assert_eq!(x.mod_square(&SM2_N).limbs, mul_m(&a, &a, &SM2_N.limbs));
    }
}

#[test]
fn modular_multiplication_for_other_moduli() {
    let mut rng = Rng(2);
    let mut moduli: Vec<U256> = vec![
        ONE,
        [2, 0, 0, 0],
        [3, 0, 0, 0],
        [7, 0, 0, 0],
        [u64::MAX, 0, 0, 0],
        [0, 1, 0, 0],
        [u64::MAX, u64::MAX, 0, 0],
        [0, 0, 1, 0],
        [1, 0, 0, 1 << 63],
        [0, 0, 0, 1 << 63],
        [0, 0, 0, 1],
        [u64::MAX; 4],
        [0xFFFF_FFFF_FFFF_FFFF, 0, u64::MAX, 0],
        [0, 0x8000_0000_0000_0000, 0, 0],
    ];
    for _ in 0..40 {
        moduli.push(rng.interesting());
    }
    moduli.retain(|m| *m != ZERO);
    for m in &moduli {
        for _ in 0..30 {
            let (a, b) = (rng.interesting(), rng.interesting());
            let (x, y) = (BigInt256::new(a), BigInt256::new(b));
            let modulus = BigInt256::new(*m);
            assert_eq!(
                x.mod_mul(&y, &modulus).limbs,
                mul_m(&a, &b, m),
                "{a:x?} {b:x?} mod {m:x?}"
            );
            assert_eq!(x.mod_square(&modulus).limbs, mul_m(&a, &a, m));
        }
    }
    assert_eq!(
        BigInt256::ONE.mod_mul(&BigInt256::ONE, &BigInt256::ZERO),
        BigInt256::ZERO
    );
}

#[test]
fn adc_sbb_compare_and_shifts() {
    for (a, b) in value_pairs(3000, 3) {
        let (x, y) = (BigInt256::new(a), BigInt256::new(b));

        let expected_order = (a[3], a[2], a[1], a[0]).cmp(&(b[3], b[2], b[1], b[0]));
        assert_eq!(x.compare(&y), expected_order);
        assert_eq!(x.cmp(&y), expected_order);
        assert_eq!(x == y, expected_order == Ordering::Equal);

        let (sum, carry) = x.add(&y);
        let (back, borrow) = sum.sub(&y);
        assert_eq!(back, x);
        assert_eq!(carry, borrow);
        assert_eq!(
            carry,
            (a[3], a[2], a[1], a[0]) > (sum.limbs[3], sum.limbs[2], sum.limbs[1], sum.limbs[0])
        );

        assert_eq!(x.mul(&y), wide_mul(&a, &b));

        let right = x.shift_right_1();
        let left = x.shift_left_1();
        for bit in 0..256 {
            let original = x.get_bit(bit);
            assert_eq!(original, (a[bit / 64] >> (bit % 64)) & 1 == 1);
            if bit > 0 {
                assert_eq!(right.get_bit(bit - 1), original);
            }
            if bit < 255 {
                assert_eq!(left.get_bit(bit + 1), original);
            }
        }
        assert!(!x.get_bit(256));
        assert_eq!(
            x.bit_length(),
            (0..256).rev().find(|&i| x.get_bit(i)).map_or(0, |i| i + 1)
        );

        assert_eq!(BigInt256::from_hex(&x.to_hex()), x);
        assert_eq!(BigInt256::from_hex(&x.to_hex_lower()), x);
        assert_eq!(BigInt256::from_be_bytes(&x.to_be_bytes()), x);
        assert_eq!(x.to_hex_lower(), x.to_hex().to_lowercase());
        assert_eq!(
            x.to_hex(),
            format!("{:016X}{:016X}{:016X}{:016X}", a[3], a[2], a[1], a[0])
        );

        assert_eq!(x.is_zero(), a == ZERO);
        assert_eq!(x.is_one(), a == ONE);
    }
}

/// mod_add subtracts at most once and mod_sub adds at most once, even for out-of-range inputs:
/// callers depend on that exact behaviour.
#[test]
fn modular_addition_keeps_single_correction_semantics() {
    let mut rng = Rng(4);
    for (a, b) in value_pairs(3000, 5) {
        for m in [P, SM2_N.limbs, rng.interesting()] {
            let (x, y, modulus) = (BigInt256::new(a), BigInt256::new(b), BigInt256::new(m));
            let (sum, carry) = x.add(&y);
            let expected = if carry || sum.compare(&modulus) != Ordering::Less {
                sum.sub(&modulus).0
            } else {
                sum
            };
            assert_eq!(x.mod_add(&y, &modulus), expected);
            let (diff, borrow) = x.sub(&y);
            let expected = if borrow { diff.add(&modulus).0 } else { diff };
            assert_eq!(x.mod_sub(&y, &modulus), expected);
        }
    }
}

#[test]
fn integer_parsing_rejects_what_it_cannot_represent() {
    let hex = BigInt256::from_hex;
    assert_eq!(hex("1").limbs, ONE);
    assert_eq!(hex("0x1").limbs, ONE);
    assert_eq!(hex("0X1").limbs, ONE);
    assert_eq!(hex("abCD").limbs, [0xabcd, 0, 0, 0]);
    assert_eq!(hex(&"f".repeat(64)).limbs, MAX);
    // None of these are numbers; ZERO is what every key check rejects.
    for invalid in [
        "", "0x", "zz", "1z", "+f", "0x0x1", "0X0x1", "é", " 1", "1 ",
    ] {
        assert_eq!(hex(invalid).limbs, ZERO, "{invalid}");
        assert!(BigInt256::try_from_hex(invalid).is_none(), "{invalid}");
    }
    assert_eq!(hex(&"0".repeat(65)).limbs, ZERO);
    assert_eq!(hex(&"f".repeat(65)).limbs, ZERO);
    assert_eq!(BigInt256::try_from_hex("10").unwrap().limbs, [16, 0, 0, 0]);

    assert_eq!(BigInt256::from_be_bytes(&[1, 2]).limbs, [0x0102, 0, 0, 0]);
    assert_eq!(BigInt256::from_be_bytes(&[]).limbs, ZERO);
    assert_eq!(BigInt256::from_be_bytes(&[5; 33]).limbs, ZERO);
    assert_eq!(BigInt256::from_be_bytes(&[0; 40]).limbs, ZERO);
}

// ---------------------------------------------------------------- tests: field

#[test]
fn field_element_operations() {
    for (a, b) in value_pairs(3000, 6) {
        let (ra, rb) = (rem(&a, &P), rem(&b, &P));
        let (x, y) = (fp(a), fp(b));
        assert_eq!(x.value.limbs, ra);
        assert_eq!(x.add(&y).value.limbs, fadd(&ra, &rb));
        assert_eq!(x.subtract(&y).value.limbs, fsub(&ra, &rb));
        assert_eq!(x.multiply(&y).value.limbs, fmul(&ra, &rb));
        assert_eq!(x.square().value.limbs, fmul(&ra, &ra));
        assert_eq!(x.double().value.limbs, fadd(&ra, &ra));
        assert_eq!(x.triple().value.limbs, fadd(&fadd(&ra, &ra), &ra));
        assert_eq!(x.negate().value.limbs, fsub(&ZERO, &ra));
    }
}

#[test]
fn inversion_against_fermat() {
    let mut inputs = field_edges();
    let mut rng = Rng(7);
    for _ in 0..150 {
        inputs.push(rng.interesting());
    }
    for a in inputs {
        let reduced_p = rem(&a, &P);
        if reduced_p != ZERO {
            assert_eq!(fp(a).invert().value.limbs, finv(&reduced_p), "{a:x?}");
        }
        if a != ZERO {
            let x = BigInt256::new(a);
            assert_eq!(
                x.mod_inverse(&SM2_P).limbs,
                finv_or_zero(&reduced_p, &P),
                "{a:x?}"
            );
            let reduced_n = rem(&a, &SM2_N.limbs);
            assert_eq!(
                x.mod_inverse(&SM2_N).limbs,
                finv_or_zero(&reduced_n, &SM2_N.limbs),
                "{a:x?}"
            );
        }
    }
    assert!(FpElement::zero().invert().is_zero());
    assert!(FpElement::one().divide(&FpElement::zero()).is_zero());
    assert_eq!(BigInt256::ZERO.mod_inverse(&SM2_N), BigInt256::ZERO);
    assert_eq!(
        BigInt256::ONE.mod_inverse(&BigInt256::ZERO),
        BigInt256::ZERO
    );
    // Composite modulus without an inverse.
    let (two, four) = (BigInt256::new([2, 0, 0, 0]), BigInt256::new([4, 0, 0, 0]));
    assert_eq!(two.mod_inverse(&four), BigInt256::ZERO);
    assert_eq!(
        BigInt256::ONE.mod_pow(&BigInt256::ZERO, &BigInt256::ONE),
        BigInt256::ZERO
    );
}

fn finv_or_zero(a: &U256, m: &U256) -> U256 {
    let mut e = *m;
    e[0] -= 2;
    let mut r = ONE;
    for i in (0..256).rev() {
        r = mul_m(&r, &r, m);
        if (e[i / 64] >> (i % 64)) & 1 == 1 {
            r = mul_m(&r, a, m);
        }
    }
    r
}

// ---------------------------------------------------------------- tests: points

fn g_ref() -> RefPoint {
    RefPoint {
        x: SM2_GX.value.limbs,
        y: SM2_GY.value.limbs,
        z: ONE,
    }
}

fn scalar_edges() -> Vec<U256> {
    let n = SM2_N.limbs;
    let mut scalars = vec![ZERO, ONE, MAX, minus(&MAX, 1), [0, 0, 0, 1 << 63]];
    for small in 1..70u64 {
        scalars.push([small, 0, 0, 0]);
        scalars.push(minus(&n, small));
        scalars.push(plus(&n, small));
    }
    scalars.push(n);
    for shift in 0..8 {
        scalars.push([1 << (shift * 8), 0, 0, 0]);
        scalars.push([0, 1 << (shift * 8), 0, 0]);
        scalars.push([0, 0, 1 << (shift * 8), 0]);
        scalars.push([0, 0, 0, 1 << (shift * 8)]);
    }
    scalars
}

/// The doubling case of the incomplete formulas occurs at k = n - 2j, covered by the edges.
#[test]
fn generator_multiplication_edges_and_random() {
    let mut scalars = scalar_edges();
    let mut rng = Rng(8);
    for _ in 0..40 {
        scalars.push(rng.interesting());
    }
    let g = ECPoint::generator();
    for k in scalars {
        let actual = g.multiply(&BigInt256::new(k));
        assert_same(&actual, &ref_mul(&g_ref(), &k), &format!("[{k:x?}]G"));
    }
}

#[test]
fn variable_base_multiplication_edges_and_random() {
    let mut rng = Rng(9);
    let bases: Vec<ECPoint> = (0..3)
        .map(|_| ECPoint::generator().multiply(&BigInt256::new(rng.u256())))
        .chain([ECPoint::generator().negate()])
        .collect();
    let mut scalars = scalar_edges();
    for _ in 0..40 {
        scalars.push(rng.interesting());
    }
    for base in &bases {
        let reference = to_ref(base);
        // Every edge with one base, a sample with the others: the reference is slow.
        for k in scalars
            .iter()
            .step_by(if base.y == bases[0].y { 1 } else { 5 })
        {
            let actual = base.multiply(&BigInt256::new(*k));
            assert_same(&actual, &ref_mul(&reference, k), &format!("[{k:x?}]P"));
        }
    }
    assert!(ECPoint::infinity().multiply(&BigInt256::ONE).is_infinity());
}

/// Invalid points must never reach the group law, for secret scalars least of all.
#[test]
fn invalid_points_give_infinity_from_every_operation() {
    let mut rng = Rng(10);
    let g = ECPoint::generator();
    let mut invalid = Vec::new();
    while invalid.len() < 3 {
        let p = ECPoint::new(fp(rng.u256()), fp(rng.u256()));
        if !p.is_on_curve() {
            invalid.push(p);
        }
    }
    // y = 0 has order 2 on the curve it implies.
    invalid.push(ECPoint::new(fp([5, 0, 0, 0]), FpElement::zero()));
    // A valid point whose small x allows x + p to fit: congruent to it, but not canonical.
    let exponent = {
        // (p + 1) / 4, for the square root in a field with p = 3 mod 4
        let mut e = plus(&P, 1);
        for _ in 0..2 {
            e = [
                (e[0] >> 1) | (e[1] << 63),
                (e[1] >> 1) | (e[2] << 63),
                (e[2] >> 1) | (e[3] << 63),
                e[3] >> 1,
            ];
        }
        e
    };
    let (x, y) = (1u64..)
        .find_map(|small| {
            let x = [small, 0, 0, 0];
            let rhs = fadd(
                &fsub(&fmul(&fmul(&x, &x), &x), &fadd(&fadd(&x, &x), &x)),
                &SM2_B.value.limbs,
            );
            let y = fpow(&rhs, &exponent);
            (fmul(&y, &y) == rhs).then_some((x, y))
        })
        .unwrap();
    assert!(ECPoint::new(fp(x), fp(y)).is_on_curve());
    invalid.push(ECPoint {
        x: FpElement {
            value: BigInt256::new(x).add(&SM2_P).0,
        },
        y: fp(y),
        infinity: false,
    });
    assert_eq!(invalid.len(), 5);
    let scalar = BigInt256::new([3, 0, 0, 0]);
    for p in &invalid {
        assert!(!p.is_on_curve());
        assert!(p.multiply(&scalar).is_infinity());
        assert!(p.twice().is_infinity());
        assert!(p.negate().is_infinity());
        assert!(p.add(&g).is_infinity());
        assert!(g.add(p).is_infinity());
        assert!(p.add(&ECPoint::infinity()).is_infinity());
        assert!(ECPoint::infinity().add(p).is_infinity());
        assert!(p.subtract(&g).is_infinity());
        assert!(g.subtract(p).is_infinity());
    }
}

#[test]
fn point_addition_cases() {
    let mut rng = Rng(11);
    let g = ECPoint::generator();
    let inf = ECPoint::infinity();
    for _ in 0..12 {
        let p = g.multiply(&BigInt256::new(rng.u256()));
        let q = g.multiply(&BigInt256::new(rng.u256()));
        let (rp, rq) = (to_ref(&p), to_ref(&q));
        assert_same(&p.add(&q), &ref_add(&rp, &rq), "P + Q");
        assert_same(&p.add(&p), &ref_double(&rp), "P + P");
        assert_same(&p.twice(), &ref_double(&rp), "2P");
        assert!(p.add(&p.negate()).is_infinity(), "P + (-P)");
        assert!(p.subtract(&p).is_infinity(), "P - P");
        assert_eq!(p.add(&inf), p);
        assert_eq!(inf.add(&p), p);
        assert!(inf.add(&inf).is_infinity());
        assert!(inf.twice().is_infinity());
        assert!(inf.negate().is_infinity());
        assert_eq!(p.negate().negate(), p);
        assert!(p.is_on_curve());
        assert_eq!(ECPoint::from_encoded(&p.to_encoded()), p);
        assert_eq!(ECPoint::from_hex_encoded(&p.to_hex_encoded()), p);
    }
    let order_two = ECPoint::new(fp([5, 0, 0, 0]), FpElement::zero());
    assert!(order_two.twice().is_infinity());
    assert!(!inf.is_on_curve(), "infinity is not a valid key");
    assert_eq!(inf.to_encoded(), vec![0x00]);
    assert_eq!(inf.to_hex_encoded(), "00");
}

#[test]
fn point_decoding_is_strict() {
    let g = ECPoint::generator();
    let text = g.to_hex_encoded();
    assert_eq!(ECPoint::from_hex_encoded(&text), g);
    assert_eq!(ECPoint::from_hex_encoded(&text.to_uppercase()), g);
    assert_eq!(ECPoint::from_encoded(&g.to_encoded()), g);
    let (x, y) = (g.x.to_hex(), g.y.to_hex());
    assert_eq!(ECPoint::from_hex(&x, &y), g);
    assert!(ECPoint::from_hex(&x, &x).is_infinity());
    assert!(ECPoint::from_hex("1", "2").is_infinity());
    assert!(ECPoint::from_hex(&x, &y[1..]).is_infinity());

    let mut broken = text.clone();
    broken.replace_range(2..4, "zz");
    let mut flipped = text.clone();
    flipped.replace_range(128..130, "00");
    for invalid in [
        String::new(),
        "00".to_string(),
        "04".to_string(),
        "05".to_string(),
        format!("0x{text}"),
        format!("{text}f"),
        format!("{text}00"),
        text[..129].to_string(),
        text[2..].to_string(),
        broken,
        flipped,
        "é".repeat(65),
        format!("+{}", &text[1..]),
    ] {
        assert!(
            ECPoint::from_hex_encoded(&invalid).is_infinity(),
            "{invalid}"
        );
        assert!(
            ECPoint::try_from_hex_encoded(&invalid).is_none(),
            "{invalid}"
        );
    }
    assert!(ECPoint::from_encoded(&[]).is_infinity());
    assert!(ECPoint::from_encoded(&[4; 64]).is_infinity());
    assert!(ECPoint::try_from_encoded(&[4; 66]).is_none());
    // Coordinates at or above p are not reduced into something else.
    let mut raw = [0xffu8; 65];
    raw[0] = 4;
    assert!(ECPoint::from_encoded(&raw).is_infinity());
}

#[test]
fn curve_membership_against_equation() {
    let mut rng = Rng(12);
    for _ in 0..200 {
        let (x, y) = (rem(&rng.u256(), &P), rem(&rng.u256(), &P));
        let p = ECPoint::new(fp(x), fp(y));
        // y^2 = x^3 - 3x + b
        let rhs = fadd(
            &fsub(&fmul(&fmul(&x, &x), &x), &fadd(&fadd(&x, &x), &x)),
            &SM2_B.value.limbs,
        );
        assert_eq!(p.is_on_curve(), fmul(&y, &y) == rhs);
    }
}
