package smx

// The SM9 extension tower, all in Montgomery form and constant time:
//
//	Fq2  = Fq[u]  / (u^2 + 2)        a0 + a1 u
//	Fq6  = Fq2[s] / (s^3 - u)        b0 + b1 s + b2 s^2, s = w^2
//	Fq12 = Fq6[w] / (w^2 - s)        c0 + c1 w
//
// This is the standard's Fq12 = Fq4[w]/(w^3 - v), Fq4 = Fq2[v]/(v^2 - u), regrouped: an
// element is sum x_j w^j with w^6 = u, and here x0, x2, x4 sit in c0 and x1, x3, x5 in
// c1. sm9Fp12Bytes converts to the standard's byte order.

type sm9Fp2 struct{ a0, a1 sm9Fp }

type sm9Fp6 struct{ b0, b1, b2 sm9Fp2 }

type sm9Fp12 struct{ c0, c1 sm9Fp6 }

// --- Fq2 ---

func sm9Fp2Add(z, x, y *sm9Fp2) {
	sm9FpAdd(&z.a0, &x.a0, &y.a0)
	sm9FpAdd(&z.a1, &x.a1, &y.a1)
}

func sm9Fp2Sub(z, x, y *sm9Fp2) {
	sm9FpSub(&z.a0, &x.a0, &y.a0)
	sm9FpSub(&z.a1, &x.a1, &y.a1)
}

func sm9Fp2Double(z, x *sm9Fp2) {
	sm9FpDouble(&z.a0, &x.a0)
	sm9FpDouble(&z.a1, &x.a1)
}

func sm9Fp2Neg(z, x *sm9Fp2) {
	sm9FpNeg(&z.a0, &x.a0)
	sm9FpNeg(&z.a1, &x.a1)
}

func sm9Fp2Conj(z, x *sm9Fp2) {
	z.a0 = x.a0
	sm9FpNeg(&z.a1, &x.a1)
}

// sm9Fp2Mul uses Karatsuba: three Fq multiplications.
func sm9Fp2Mul(z, x, y *sm9Fp2) {
	var v0, v1, s, t sm9Fp
	sm9FpMul(&v0, &x.a0, &y.a0)
	sm9FpMul(&v1, &x.a1, &y.a1)
	sm9FpAdd(&s, &x.a0, &x.a1)
	sm9FpAdd(&t, &y.a0, &y.a1)
	sm9FpMul(&s, &s, &t)
	sm9FpSub(&s, &s, &v0)
	sm9FpSub(&z.a1, &s, &v1)
	sm9FpDouble(&v1, &v1)
	sm9FpSub(&z.a0, &v0, &v1) // a0 b0 - 2 a1 b1
}

// sm9Fp2Sqr: (a0 + a1 u)^2 = (a0 + a1)(a0 - 2 a1) + a0 a1 + 2 a0 a1 u.
func sm9Fp2Sqr(z, x *sm9Fp2) {
	var p, s, d sm9Fp
	sm9FpMul(&p, &x.a0, &x.a1)
	sm9FpAdd(&s, &x.a0, &x.a1)
	sm9FpDouble(&d, &x.a1)
	sm9FpSub(&d, &x.a0, &d)
	sm9FpMul(&s, &s, &d)
	sm9FpAdd(&z.a0, &s, &p)
	sm9FpDouble(&z.a1, &p)
}

// sm9Fp2MulFp multiplies by an element of Fq.
func sm9Fp2MulFp(z, x *sm9Fp2, k *sm9Fp) {
	sm9FpMul(&z.a0, &x.a0, k)
	sm9FpMul(&z.a1, &x.a1, k)
}

// sm9Fp2MulU multiplies by u: (a0 + a1 u) u = -2 a1 + a0 u.
func sm9Fp2MulU(z, x *sm9Fp2) {
	var t sm9Fp
	sm9FpDouble(&t, &x.a1)
	a0 := x.a0
	sm9FpNeg(&z.a0, &t)
	z.a1 = a0
}

// sm9Fp2Inv: 1/(a0 + a1 u) = (a0 - a1 u) / (a0^2 + 2 a1^2); zero maps to zero.
func sm9Fp2Inv(z, x *sm9Fp2) {
	var n, t sm9Fp
	sm9FpSqr(&n, &x.a0)
	sm9FpSqr(&t, &x.a1)
	sm9FpDouble(&t, &t)
	sm9FpAdd(&n, &n, &t)
	sm9FpInv(&n, &n)
	sm9FpMul(&z.a0, &x.a0, &n)
	sm9FpMul(&t, &x.a1, &n)
	sm9FpNeg(&z.a1, &t)
}

func sm9Fp2IsZeroMask(x *sm9Fp2) uint64 {
	return sm9FpIsZeroMask(&x.a0) & sm9FpIsZeroMask(&x.a1)
}

func sm9Fp2EqualMask(x, y *sm9Fp2) uint64 {
	return sm9FpEqualMask(&x.a0, &y.a0) & sm9FpEqualMask(&x.a1, &y.a1)
}

func sm9Fp2Select(z, x *sm9Fp2, mask uint64) {
	sm9FpSelect(&z.a0, &x.a0, mask)
	sm9FpSelect(&z.a1, &x.a1, mask)
}

func sm9Fp2One() sm9Fp2 { return sm9Fp2{a0: sm9FpOne} }

// --- Fq6 ---

func sm9Fp6Add(z, x, y *sm9Fp6) {
	sm9Fp2Add(&z.b0, &x.b0, &y.b0)
	sm9Fp2Add(&z.b1, &x.b1, &y.b1)
	sm9Fp2Add(&z.b2, &x.b2, &y.b2)
}

func sm9Fp6Sub(z, x, y *sm9Fp6) {
	sm9Fp2Sub(&z.b0, &x.b0, &y.b0)
	sm9Fp2Sub(&z.b1, &x.b1, &y.b1)
	sm9Fp2Sub(&z.b2, &x.b2, &y.b2)
}

func sm9Fp6Double(z, x *sm9Fp6) {
	sm9Fp2Double(&z.b0, &x.b0)
	sm9Fp2Double(&z.b1, &x.b1)
	sm9Fp2Double(&z.b2, &x.b2)
}

func sm9Fp6Neg(z, x *sm9Fp6) {
	sm9Fp2Neg(&z.b0, &x.b0)
	sm9Fp2Neg(&z.b1, &x.b1)
	sm9Fp2Neg(&z.b2, &x.b2)
}

// sm9Fp6MulS multiplies by s: (b0, b1, b2) s = (u b2, b0, b1).
func sm9Fp6MulS(z, x *sm9Fp6) {
	var t sm9Fp2
	sm9Fp2MulU(&t, &x.b2)
	z.b2 = x.b1
	z.b1 = x.b0
	z.b0 = t
}

// sm9Fp6Mul uses Karatsuba: six Fq2 multiplications.
func sm9Fp6Mul(z, x, y *sm9Fp6) {
	var t0, t1, t2, c0, c1, c2, a, b sm9Fp2
	sm9Fp2Mul(&t0, &x.b0, &y.b0)
	sm9Fp2Mul(&t1, &x.b1, &y.b1)
	sm9Fp2Mul(&t2, &x.b2, &y.b2)

	sm9Fp2Add(&a, &x.b1, &x.b2)
	sm9Fp2Add(&b, &y.b1, &y.b2)
	sm9Fp2Mul(&c0, &a, &b)
	sm9Fp2Sub(&c0, &c0, &t1)
	sm9Fp2Sub(&c0, &c0, &t2)
	sm9Fp2MulU(&c0, &c0)
	sm9Fp2Add(&c0, &c0, &t0)

	sm9Fp2Add(&a, &x.b0, &x.b1)
	sm9Fp2Add(&b, &y.b0, &y.b1)
	sm9Fp2Mul(&c1, &a, &b)
	sm9Fp2Sub(&c1, &c1, &t0)
	sm9Fp2Sub(&c1, &c1, &t1)
	sm9Fp2MulU(&a, &t2)
	sm9Fp2Add(&c1, &c1, &a)

	sm9Fp2Add(&a, &x.b0, &x.b2)
	sm9Fp2Add(&b, &y.b0, &y.b2)
	sm9Fp2Mul(&c2, &a, &b)
	sm9Fp2Sub(&c2, &c2, &t0)
	sm9Fp2Sub(&c2, &c2, &t2)
	sm9Fp2Add(&c2, &c2, &t1)

	z.b0, z.b1, z.b2 = c0, c1, c2
}

// sm9Fp6MulBy01 multiplies by the sparse element c0 + c1 s.
func sm9Fp6MulBy01(z *sm9Fp6, c0, c1 *sm9Fp2) {
	var a, b, t, t0, t1, t2 sm9Fp2
	sm9Fp2Mul(&a, &z.b0, c0)
	sm9Fp2Mul(&b, &z.b1, c1)

	sm9Fp2Add(&t, &z.b1, &z.b2)
	sm9Fp2Mul(&t0, c1, &t)
	sm9Fp2Sub(&t0, &t0, &b)
	sm9Fp2MulU(&t0, &t0)
	sm9Fp2Add(&t0, &t0, &a)

	sm9Fp2Add(&t, &z.b0, &z.b2)
	sm9Fp2Mul(&t2, c0, &t)
	sm9Fp2Sub(&t2, &t2, &a)
	sm9Fp2Add(&t2, &t2, &b)

	sm9Fp2Add(&t1, c0, c1)
	sm9Fp2Add(&t, &z.b0, &z.b1)
	sm9Fp2Mul(&t1, &t1, &t)
	sm9Fp2Sub(&t1, &t1, &a)
	sm9Fp2Sub(&t1, &t1, &b)

	z.b0, z.b1, z.b2 = t0, t1, t2
}

// sm9Fp6MulBy1 multiplies by the sparse element c1 s.
func sm9Fp6MulBy1(z *sm9Fp6, c1 *sm9Fp2) {
	var b, t, t0, t1 sm9Fp2
	sm9Fp2Mul(&b, &z.b1, c1)

	sm9Fp2Add(&t, &z.b1, &z.b2)
	sm9Fp2Mul(&t0, c1, &t)
	sm9Fp2Sub(&t0, &t0, &b)
	sm9Fp2MulU(&t0, &t0)

	sm9Fp2Add(&t, &z.b0, &z.b1)
	sm9Fp2Mul(&t1, c1, &t)
	sm9Fp2Sub(&t1, &t1, &b)

	z.b0, z.b1, z.b2 = t0, t1, b
}

// sm9Fp6Inv inverts in Fq2[s]/(s^3 - u); zero maps to zero.
func sm9Fp6Inv(z, x *sm9Fp6) {
	var t0, t1, t2, t3, t4, t5, c0, c1, c2, n, d sm9Fp2
	sm9Fp2Sqr(&t0, &x.b0)
	sm9Fp2Sqr(&t1, &x.b1)
	sm9Fp2Sqr(&t2, &x.b2)
	sm9Fp2Mul(&t3, &x.b0, &x.b1)
	sm9Fp2Mul(&t4, &x.b0, &x.b2)
	sm9Fp2Mul(&t5, &x.b1, &x.b2)
	sm9Fp2MulU(&c0, &t5)
	sm9Fp2Sub(&c0, &t0, &c0) // b0^2 - u b1 b2
	sm9Fp2MulU(&c1, &t2)
	sm9Fp2Sub(&c1, &c1, &t3) // u b2^2 - b0 b1
	sm9Fp2Sub(&c2, &t1, &t4) // b1^2 - b0 b2
	sm9Fp2Mul(&n, &x.b0, &c0)
	sm9Fp2Mul(&d, &x.b2, &c1)
	sm9Fp2Mul(&t0, &x.b1, &c2)
	sm9Fp2Add(&d, &d, &t0)
	sm9Fp2MulU(&d, &d)
	sm9Fp2Add(&n, &n, &d)
	sm9Fp2Inv(&n, &n)
	sm9Fp2Mul(&z.b0, &c0, &n)
	sm9Fp2Mul(&z.b1, &c1, &n)
	sm9Fp2Mul(&z.b2, &c2, &n)
}

// --- Fq12 ---

func sm9Fp12One() sm9Fp12 {
	var z sm9Fp12
	z.c0.b0.a0 = sm9FpOne
	return z
}

func sm9Fp12Mul(z, x, y *sm9Fp12) {
	var a, b, c, d sm9Fp6
	sm9Fp6Add(&a, &x.c0, &x.c1)
	sm9Fp6Add(&b, &y.c0, &y.c1)
	sm9Fp6Mul(&a, &a, &b)
	sm9Fp6Mul(&b, &x.c0, &y.c0)
	sm9Fp6Mul(&c, &x.c1, &y.c1)
	sm9Fp6Sub(&a, &a, &b)
	sm9Fp6Sub(&z.c1, &a, &c)
	sm9Fp6MulS(&d, &c)
	sm9Fp6Add(&z.c0, &d, &b)
}

// sm9Fp12Sqr: (c0 + c1 w)^2 = c0^2 + s c1^2 + 2 c0 c1 w, with two Fq6 multiplications.
func sm9Fp12Sqr(z, x *sm9Fp12) {
	var d, e, p sm9Fp6
	sm9Fp6Sub(&d, &x.c0, &x.c1)
	sm9Fp6MulS(&e, &x.c1)
	sm9Fp6Sub(&e, &x.c0, &e)
	sm9Fp6Mul(&p, &x.c0, &x.c1)
	sm9Fp6Mul(&d, &d, &e)
	sm9Fp6Add(&d, &d, &p)
	sm9Fp6Double(&z.c1, &p)
	sm9Fp6MulS(&p, &p)
	sm9Fp6Add(&z.c0, &d, &p)
}

// sm9Fp12Conj sets z = x^(q^6): w^(q^6) = -w and Fq6 is fixed. For elements of the
// cyclotomic subgroup, which is where every pairing value lives, it is the inverse.
func sm9Fp12Conj(z, x *sm9Fp12) {
	z.c0 = x.c0
	sm9Fp6Neg(&z.c1, &x.c1)
}

// sm9Fp12Inv: (c0 + c1 w)^-1 = (c0 - c1 w) / (c0^2 - s c1^2).
func sm9Fp12Inv(z, x *sm9Fp12) {
	var t0, t1 sm9Fp6
	sm9Fp6Mul(&t0, &x.c0, &x.c0)
	sm9Fp6Mul(&t1, &x.c1, &x.c1)
	sm9Fp6MulS(&t1, &t1)
	sm9Fp6Sub(&t0, &t0, &t1)
	sm9Fp6Inv(&t0, &t0)
	sm9Fp6Mul(&z.c0, &x.c0, &t0)
	sm9Fp6Mul(&z.c1, &x.c1, &t0)
	sm9Fp6Neg(&z.c1, &z.c1)
}

// sm9Fp12MulBy014 multiplies by the sparse line value l0 + l1 w^2 + l4 w^3 (l0 in c0.b0,
// l1 in c0.b1, l4 in c1.b1).
func sm9Fp12MulBy014(z *sm9Fp12, l0, l1, l4 *sm9Fp2) {
	var a, b sm9Fp6
	var d sm9Fp2
	a = z.c0
	sm9Fp6MulBy01(&a, l0, l1)
	b = z.c1
	sm9Fp6MulBy1(&b, l4)
	sm9Fp2Add(&d, l1, l4)
	sm9Fp6Add(&z.c1, &z.c1, &z.c0)
	sm9Fp6MulBy01(&z.c1, l0, &d)
	sm9Fp6Sub(&z.c1, &z.c1, &a)
	sm9Fp6Sub(&z.c1, &z.c1, &b)
	sm9Fp6MulS(&z.c0, &b)
	sm9Fp6Add(&z.c0, &z.c0, &a)
}

// sm9Fp12Frob sets z = x^(q^k) for k in 1..3: the coefficient of w^j is conjugated for
// odd k and multiplied by gamma_k^j, which lies in Fq.
func sm9Fp12Frob(z, x *sm9Fp12, k int) {
	g := &sm9Frob[k-1]
	coef := [6]*sm9Fp2{&x.c0.b0, &x.c1.b0, &x.c0.b1, &x.c1.b1, &x.c0.b2, &x.c1.b2}
	var out [6]sm9Fp2
	for j := 0; j < 6; j++ {
		if k%2 == 1 {
			sm9Fp2Conj(&out[j], coef[j])
		} else {
			out[j] = *coef[j]
		}
		if j > 0 {
			sm9Fp2MulFp(&out[j], &out[j], &g[j-1])
		}
	}
	z.c0.b0, z.c1.b0, z.c0.b1, z.c1.b1, z.c0.b2, z.c1.b2 = out[0], out[1], out[2], out[3], out[4], out[5]
}

// sm9Fp12CycSqr squares an element of the cyclotomic subgroup with the Granger-Scott
// formulas: 6 Fq2 squarings in place of a full Fq12 squaring.
func sm9Fp12CycSqr(z, x *sm9Fp12) {
	var t [9]sm9Fp2
	sm9Fp2Sqr(&t[0], &x.c1.b1)
	sm9Fp2Sqr(&t[1], &x.c0.b0)
	sm9Fp2Add(&t[6], &x.c1.b1, &x.c0.b0)
	sm9Fp2Sqr(&t[6], &t[6])
	sm9Fp2Sub(&t[6], &t[6], &t[0])
	sm9Fp2Sub(&t[6], &t[6], &t[1])
	sm9Fp2Sqr(&t[2], &x.c0.b2)
	sm9Fp2Sqr(&t[3], &x.c1.b0)
	sm9Fp2Add(&t[7], &x.c0.b2, &x.c1.b0)
	sm9Fp2Sqr(&t[7], &t[7])
	sm9Fp2Sub(&t[7], &t[7], &t[2])
	sm9Fp2Sub(&t[7], &t[7], &t[3])
	sm9Fp2Sqr(&t[4], &x.c1.b2)
	sm9Fp2Sqr(&t[5], &x.c0.b1)
	sm9Fp2Add(&t[8], &x.c1.b2, &x.c0.b1)
	sm9Fp2Sqr(&t[8], &t[8])
	sm9Fp2Sub(&t[8], &t[8], &t[4])
	sm9Fp2Sub(&t[8], &t[8], &t[5])
	sm9Fp2MulU(&t[8], &t[8])

	sm9Fp2MulU(&t[0], &t[0])
	sm9Fp2Add(&t[0], &t[0], &t[1])
	sm9Fp2MulU(&t[2], &t[2])
	sm9Fp2Add(&t[2], &t[2], &t[3])
	sm9Fp2MulU(&t[4], &t[4])
	sm9Fp2Add(&t[4], &t[4], &t[5])

	var r sm9Fp12
	sm9Fp2Sub(&r.c0.b0, &t[0], &x.c0.b0)
	sm9Fp2Double(&r.c0.b0, &r.c0.b0)
	sm9Fp2Add(&r.c0.b0, &r.c0.b0, &t[0])
	sm9Fp2Sub(&r.c0.b1, &t[2], &x.c0.b1)
	sm9Fp2Double(&r.c0.b1, &r.c0.b1)
	sm9Fp2Add(&r.c0.b1, &r.c0.b1, &t[2])
	sm9Fp2Sub(&r.c0.b2, &t[4], &x.c0.b2)
	sm9Fp2Double(&r.c0.b2, &r.c0.b2)
	sm9Fp2Add(&r.c0.b2, &r.c0.b2, &t[4])

	sm9Fp2Add(&r.c1.b0, &t[8], &x.c1.b0)
	sm9Fp2Double(&r.c1.b0, &r.c1.b0)
	sm9Fp2Add(&r.c1.b0, &r.c1.b0, &t[8])
	sm9Fp2Add(&r.c1.b1, &t[6], &x.c1.b1)
	sm9Fp2Double(&r.c1.b1, &r.c1.b1)
	sm9Fp2Add(&r.c1.b1, &r.c1.b1, &t[6])
	sm9Fp2Add(&r.c1.b2, &t[7], &x.c1.b2)
	sm9Fp2Double(&r.c1.b2, &r.c1.b2)
	sm9Fp2Add(&r.c1.b2, &r.c1.b2, &t[7])
	*z = r
}

// sm9Fp12Coefs returns the coefficients of w^0..w^5.
func (x *sm9Fp12) coefs() [6]*sm9Fp2 {
	return [6]*sm9Fp2{&x.c0.b0, &x.c1.b0, &x.c0.b1, &x.c1.b1, &x.c0.b2, &x.c1.b2}
}

// sm9Fp12Bytes encodes x as the standard does, 384 bytes: Fq4 coefficients c2, c1, c0 of
// 1, w, w^2, each Fq4 c_i = x_i + x_{i+3} v as x_{i+3} || x_i, each Fq2 as a1 || a0.
func sm9Fp12Bytes(out *[384]byte, x *sm9Fp12) {
	c := x.coefs()
	off := 0
	for _, i := range [3]int{2, 1, 0} {
		for _, j := range [2]int{i + 3, i} {
			sm9FpPutBytes(out[off:], &c[j].a1)
			sm9FpPutBytes(out[off+32:], &c[j].a0)
			off += 64
		}
	}
}

// sm9Fp12EqualMask returns all ones if x == y.
func sm9Fp12EqualMask(x, y *sm9Fp12) uint64 {
	cx, cy := x.coefs(), y.coefs()
	m := ^uint64(0)
	for i := range cx {
		m &= sm9Fp2EqualMask(cx[i], cy[i])
	}
	return m
}

// sm9Fp12Select sets z to x when mask is all ones.
func sm9Fp12Select(z, x *sm9Fp12, mask uint64) {
	cz, cx := z.coefs(), x.coefs()
	for i := range cz {
		sm9Fp2Select(cz[i], cx[i], mask)
	}
}

// sm9Frob[k-1][j-1] is gamma_k^j with gamma_k = u^((q^k-1)/6), which lies in Fq: under
// x -> x^(q^k) the coefficient of w^j picks up this factor.
var (
	sm9Frob = [3][5]sm9Fp{
		{
			sm9Fp{0x1A98DFBD4575299F, 0x9EC8547B245C54FD, 0xF51F5EAC13DF846C, 0x9EF74015D5A16393},
			sm9Fp{0xB626197DCE4736CA, 0x08296B3557ED0186, 0x9C705DB2FD91512A, 0x1C753E748601C992},
			sm9Fp{0x39B4EF0F3EE72529, 0xDB043BF508582782, 0xB8554AB054AC91E3, 0x9848EEC25498CAB5},
			sm9Fp{0x81054FCD94E9C1C4, 0x4C0E91CB8CE2DF3E, 0x4877B452E8AEDFB4, 0x88F53E748B491776},
			sm9Fp{0x048BAA79DCC34107, 0x5E2E7AC4FE76C161, 0x99399754365BD4BC, 0xAF91AEAC819B0E13},
		},
		{
			sm9Fp{0xB626197DCE4736CA, 0x08296B3557ED0186, 0x9C705DB2FD91512A, 0x1C753E748601C992},
			sm9Fp{0x81054FCD94E9C1C4, 0x4C0E91CB8CE2DF3E, 0x4877B452E8AEDFB4, 0x88F53E748B491776},
			sm9Fp{0xCADF364FC6A28AFA, 0x43E5269634F5DDB7, 0xAC07569FEB1D8E8A, 0x6C80000005474DE3},
			sm9Fp{0x2F4981AA150A0EB3, 0x19C92815C28DED55, 0x39934D9CF7FD761B, 0x99CAC18B7CA1DD5F},
			sm9Fp{0x646A4B5A4E6783B9, 0xD5E4017F8D980F9D, 0x8D8BF6FD0CDFE790, 0x2D4AC18B775A8F7B},
		},
		{
			sm9Fp{0x39B4EF0F3EE72529, 0xDB043BF508582782, 0xB8554AB054AC91E3, 0x9848EEC25498CAB5},
			sm9Fp{0xCADF364FC6A28AFA, 0x43E5269634F5DDB7, 0xAC07569FEB1D8E8A, 0x6C80000005474DE3},
			sm9Fp{0xABBAAC18A46A2054, 0x46EE57561222C759, 0x1DAE609FA0E23561, 0x1DF7113DAE0ADC3C},
			sm9Fp{0x1A9064D81CAEBA83, 0xDE0D6CB4E5851124, 0x29FC54B00A7138BA, 0x49BFFFFFFD5C590E},
			sm9Fp{0x39B4EF0F3EE72529, 0xDB043BF508582782, 0xB8554AB054AC91E3, 0x9848EEC25498CAB5},
		},
	}
)
