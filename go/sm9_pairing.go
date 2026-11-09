package smx

// The R-ate pairing of GB/T 38635 with a projective (Jacobian) Miller loop, sparse line
// multiplication and a BN final exponentiation. It returns exactly the values of the
// standard's affine description: the line values here differ from it only by factors in
// Fq2, which the final exponentiation removes.
//
// Every step depends only on the public loop constant 6t+2 and the public exponent, so a
// pairing with a secret argument (a user's encryption key) runs in constant time.

const (
	// sm9T is the BN parameter t.
	sm9T = 0x600000000058F98A
	// sm9AteHi and sm9AteLo are the 66-bit loop constant a = 6t + 2.
	sm9AteHi = 0x2
	sm9AteLo = 0x400000000215D93E
	// sm9AteBits is the bit length of a.
	sm9AteBits = 66
)

// sm9LineDouble returns the tangent line at t evaluated at the point (xp, -yp negated
// already in nyp), and sets t = 2t. With t = (X, Y, Z) the line, scaled by 2YZ^3, is
// (2Y^2 - 3X^3) + (3X^2 Z^2 xP) w^2 - (2YZ^3 yP) w^3.
func sm9LineDouble(t *sm9G2Jac, xp, nyp *sm9Fp) (l0, l1, l4 sm9Fp2) {
	var a, b, c, d, e, f, zz, x3, y3, z3, tmp sm9Fp2
	sm9Fp2Sqr(&zz, &t.z)
	sm9Fp2Sqr(&a, &t.x)
	sm9Fp2Sqr(&b, &t.y)
	sm9Fp2Double(&e, &a)
	sm9Fp2Add(&e, &e, &a) // 3X^2

	// The line.
	sm9Fp2Mul(&tmp, &e, &t.x)
	sm9Fp2Double(&l0, &b)
	sm9Fp2Sub(&l0, &l0, &tmp)
	sm9Fp2Mul(&l1, &e, &zz)
	sm9Fp2MulFp(&l1, &l1, xp)
	sm9Fp2Mul(&z3, &t.y, &t.z)
	sm9Fp2Double(&z3, &z3) // 2YZ
	sm9Fp2Mul(&l4, &z3, &zz)
	sm9Fp2MulFp(&l4, &l4, nyp)

	// The doubling, dbl-2009-l.
	sm9Fp2Sqr(&c, &b)
	sm9Fp2Add(&d, &t.x, &b)
	sm9Fp2Sqr(&d, &d)
	sm9Fp2Sub(&d, &d, &a)
	sm9Fp2Sub(&d, &d, &c)
	sm9Fp2Double(&d, &d)
	sm9Fp2Sqr(&f, &e)
	sm9Fp2Double(&tmp, &d)
	sm9Fp2Sub(&x3, &f, &tmp)
	sm9Fp2Sub(&tmp, &d, &x3)
	sm9Fp2Mul(&y3, &e, &tmp)
	sm9Fp2Double(&c, &c)
	sm9Fp2Double(&c, &c)
	sm9Fp2Double(&c, &c)
	sm9Fp2Sub(&y3, &y3, &c)
	t.x, t.y, t.z = x3, y3, z3
	return
}

// sm9LineAdd returns the line through t and the affine q evaluated at P, and sets
// t = t + q (madd-2004-hmv). With H = xQ Z^2 - X, r = yQ Z^3 - Y and Z3 = Z H the line,
// scaled by Z3, is (yQ Z3 - r xQ) + (r xP) w^2 - (Z3 yP) w^3. t must differ from +-q,
// which holds for every step of the loop when q has order N.
func sm9LineAdd(t *sm9G2Jac, q *sm9G2Aff, xp, nyp *sm9Fp) (l0, l1, l4 sm9Fp2) {
	var zz, u2, s2, h, r, hh, hhh, v, x3, y3, z3, tmp sm9Fp2
	sm9Fp2Sqr(&zz, &t.z)
	sm9Fp2Mul(&u2, &q.x, &zz)
	sm9Fp2Mul(&s2, &q.y, &t.z)
	sm9Fp2Mul(&s2, &s2, &zz)
	sm9Fp2Sub(&h, &u2, &t.x)
	sm9Fp2Sub(&r, &s2, &t.y)
	sm9Fp2Mul(&z3, &t.z, &h)

	sm9Fp2Mul(&l0, &q.y, &z3)
	sm9Fp2Mul(&tmp, &r, &q.x)
	sm9Fp2Sub(&l0, &l0, &tmp)
	sm9Fp2MulFp(&l1, &r, xp)
	sm9Fp2MulFp(&l4, &z3, nyp)

	sm9Fp2Sqr(&hh, &h)
	sm9Fp2Mul(&hhh, &hh, &h)
	sm9Fp2Mul(&v, &t.x, &hh)
	sm9Fp2Sqr(&x3, &r)
	sm9Fp2Sub(&x3, &x3, &hhh)
	sm9Fp2Double(&tmp, &v)
	sm9Fp2Sub(&x3, &x3, &tmp)
	sm9Fp2Sub(&tmp, &v, &x3)
	sm9Fp2Mul(&y3, &r, &tmp)
	sm9Fp2Mul(&tmp, &t.y, &hhh)
	sm9Fp2Sub(&y3, &y3, &tmp)
	t.x, t.y, t.z = x3, y3, z3
	return
}

// sm9MillerLoop computes the R-ate Miller function f_{a,Q}(P) times the two final lines.
func sm9MillerLoop(p *sm9G1Aff, q *sm9G2Aff) sm9Fp12 {
	xp := p.x
	var nyp sm9Fp
	sm9FpNeg(&nyp, &p.y)

	f := sm9Fp12One()
	t := q.jac()
	for i := sm9AteBits - 2; i >= 0; i-- {
		l0, l1, l4 := sm9LineDouble(&t, &xp, &nyp)
		sm9Fp12Sqr(&f, &f)
		sm9Fp12MulBy014(&f, &l0, &l1, &l4)
		var bit uint64
		if i >= 64 {
			bit = (sm9AteHi >> uint(i-64)) & 1
		} else {
			bit = (sm9AteLo >> uint(i)) & 1
		}
		if bit == 1 { // public loop constant
			l0, l1, l4 = sm9LineAdd(&t, q, &xp, &nyp)
			sm9Fp12MulBy014(&f, &l0, &l1, &l4)
		}
	}
	q1 := q.frob()
	q2 := q1.frob()
	sm9Fp2Neg(&q2.y, &q2.y)
	l0, l1, l4 := sm9LineAdd(&t, &q1, &xp, &nyp)
	sm9Fp12MulBy014(&f, &l0, &l1, &l4)
	l0, l1, l4 = sm9LineAdd(&t, &q2, &xp, &nyp)
	sm9Fp12MulBy014(&f, &l0, &l1, &l4)
	return f
}

// sm9CycExpT sets z = x^t for x in the cyclotomic subgroup.
func sm9CycExpT(z, x *sm9Fp12) {
	r := *x
	for i := 61; i >= 0; i-- { // t has 63 bits; the top one is the initial value
		sm9Fp12CycSqr(&r, &r)
		if (uint64(sm9T)>>uint(i))&1 == 1 {
			sm9Fp12Mul(&r, &r, x)
		}
	}
	*z = r
}

// sm9FinalExp raises f to (q^12 - 1)/N. The easy part is (q^6 - 1)(q^2 + 1); the hard
// part (q^4 - q^2 + 1)/N = l0 + l1 q + l2 q^2 + q^3 with l2 = 6t^2 + 1,
// l1 = -36t^3 - 18t^2 - 12t + 1, l0 = -36t^3 - 30t^2 - 18t - 2, evaluated with the
// addition chain of Scott et al., "On the final exponentiation for calculating pairings
// on ordinary elliptic curves" (2009). The exponent is exactly the standard's.
func sm9FinalExp(f *sm9Fp12) sm9Fp12 {
	var t0, t1, g sm9Fp12
	sm9Fp12Conj(&t0, f)
	sm9Fp12Inv(&t1, f)
	sm9Fp12Mul(&g, &t0, &t1)
	sm9Fp12Frob(&t0, &g, 2)
	sm9Fp12Mul(&g, &t0, &g)

	var ft, ft2, ft3, y0, y1, y2, y3, y4, y5, y6, tmp sm9Fp12
	sm9CycExpT(&ft, &g)
	sm9CycExpT(&ft2, &ft)
	sm9CycExpT(&ft3, &ft2)

	sm9Fp12Frob(&y0, &g, 1)
	sm9Fp12Frob(&tmp, &g, 2)
	sm9Fp12Mul(&y0, &y0, &tmp)
	sm9Fp12Frob(&tmp, &g, 3)
	sm9Fp12Mul(&y0, &y0, &tmp)
	sm9Fp12Conj(&y1, &g)
	sm9Fp12Frob(&y2, &ft2, 2)
	sm9Fp12Frob(&y3, &ft, 1)
	sm9Fp12Conj(&y3, &y3)
	sm9Fp12Frob(&y4, &ft2, 1)
	sm9Fp12Mul(&y4, &y4, &ft)
	sm9Fp12Conj(&y4, &y4)
	sm9Fp12Conj(&y5, &ft2)
	sm9Fp12Frob(&y6, &ft3, 1)
	sm9Fp12Mul(&y6, &y6, &ft3)
	sm9Fp12Conj(&y6, &y6)

	sm9Fp12CycSqr(&t0, &y6)
	sm9Fp12Mul(&t0, &t0, &y4)
	sm9Fp12Mul(&t0, &t0, &y5)
	sm9Fp12Mul(&t1, &y3, &y5)
	sm9Fp12Mul(&t1, &t1, &t0)
	sm9Fp12Mul(&t0, &t0, &y2)
	sm9Fp12CycSqr(&t1, &t1)
	sm9Fp12Mul(&t1, &t1, &t0)
	sm9Fp12CycSqr(&t1, &t1)
	sm9Fp12Mul(&t0, &t1, &y1)
	sm9Fp12Mul(&t1, &t1, &y0)
	sm9Fp12CycSqr(&t0, &t0)
	sm9Fp12Mul(&t0, &t0, &t1)
	return t0
}

// sm9Pair returns e(p, q) for finite points of G1 and G2.
func sm9Pair(p *sm9G1Aff, q *sm9G2Aff) sm9Fp12 {
	f := sm9MillerLoop(p, q)
	return sm9FinalExp(&f)
}

// sm9GTExp sets z = x^k for x in GT and k below 2^256, in constant time with respect to
// k: signed 5-bit windows, a masked scan of the whole table per digit, and conjugation
// (the inverse in GT) selected by mask for negative digits.
func sm9GTExp(z, x *sm9Fp12, k *[4]uint64) {
	var table [varTableSize]sm9Fp12
	table[0] = *x
	for i := 1; i < varTableSize; i++ {
		if i%2 == 1 {
			sm9Fp12CycSqr(&table[i], &table[i/2])
		} else {
			sm9Fp12Mul(&table[i], &table[i-1], x)
		}
	}
	acc := sm9Fp12One()
	one := sm9Fp12One()
	var entry, neg sm9Fp12
	for w := varWindows - 1; w >= 0; w-- {
		if w != varWindows-1 {
			for i := 0; i < varWindow; i++ {
				sm9Fp12CycSqr(&acc, &acc)
			}
		}
		magnitude, negative := boothDigit(k, uint(w)*varWindow, varWindow)
		entry = one
		for i := range table {
			sm9Fp12Select(&entry, &table[i], ctEqMask(uint64(i+1), magnitude))
		}
		sm9Fp12Conj(&neg, &entry)
		sm9Fp12Select(&entry, &neg, negative)
		sm9Fp12Mul(&acc, &acc, &entry)
	}
	*z = acc
	for i := range table {
		table[i] = sm9Fp12{}
	}
}
