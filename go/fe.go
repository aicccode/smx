package smx

import "math/bits"

// fe is a field element modulo the SM2 prime p, in Montgomery form with R = 2^256
// (the value v is stored as v*R mod p) and four little-endian limbs.
//
// Every function here runs in time independent of the limb values: carries come
// from math/bits intrinsics and reductions use masks rather than branches. Output
// parameters may alias inputs.
type fe [4]uint64

const (
	p0 = 0xFFFFFFFFFFFFFFFF
	p1 = 0xFFFFFFFF00000000
	p2 = 0xFFFFFFFFFFFFFFFF
	p3 = 0xFFFFFFFEFFFFFFFF
)

var (
	// feOne is 1 in Montgomery form (R mod p).
	feOne = fe{0x0000000000000001, 0x00000000FFFFFFFF, 0x0000000000000000, 0x0000000100000000}
	// feRR is R^2 mod p, which converts into Montgomery form.
	feRR = fe{0x0000000200000003, 0x00000002FFFFFFFF, 0x0000000100000001, 0x0000000400000002}
	// feB is the curve coefficient b in Montgomery form.
	feB = fe{0x90D230632BC0DD42, 0x71CF379AE9B537AB, 0x527981505EA51C3C, 0x240FE188BA20E2C8}
)

// feMontReduce sets z to (t7..t0) / R mod p.
//
// p is congruent to -1 modulo 2^64, so the Montgomery quotient digit is simply the
// lowest limb q, and q*p = q*2^256 - q*2^224 - q*2^96 + q*2^64 - q needs shifts only.
// Each round cancels one limb. The input must be below p*R, which gives a result below
// 2p before the final conditional subtraction.
func feMontReduce(z *fe, t0, t1, t2, t3, t4, t5, t6, t7 uint64) {
	var a1, a2, a3, a4, c, b uint64

	a1, b = bits.Sub64(t0, t0<<32, 0)
	a2, b = bits.Sub64(0, t0>>32, b)
	a3, b = bits.Sub64(0, t0<<32, b)
	a4, _ = bits.Sub64(t0, t0>>32, b)
	t1, c = bits.Add64(t1, a1, 0)
	t2, c = bits.Add64(t2, a2, c)
	t3, c = bits.Add64(t3, a3, c)
	t4, c = bits.Add64(t4, a4, c)

	// a4 is at most 2^64 - 2^32 here, so absorbing the previous carry cannot overflow.
	a1, b = bits.Sub64(t1, t1<<32, 0)
	a2, b = bits.Sub64(0, t1>>32, b)
	a3, b = bits.Sub64(0, t1<<32, b)
	a4, _ = bits.Sub64(t1, t1>>32, b)
	t2, b = bits.Add64(t2, a1, 0)
	t3, b = bits.Add64(t3, a2, b)
	t4, b = bits.Add64(t4, a3, b)
	t5, c = bits.Add64(t5, a4+c, b)

	a1, b = bits.Sub64(t2, t2<<32, 0)
	a2, b = bits.Sub64(0, t2>>32, b)
	a3, b = bits.Sub64(0, t2<<32, b)
	a4, _ = bits.Sub64(t2, t2>>32, b)
	t3, b = bits.Add64(t3, a1, 0)
	t4, b = bits.Add64(t4, a2, b)
	t5, b = bits.Add64(t5, a3, b)
	t6, c = bits.Add64(t6, a4+c, b)

	a1, b = bits.Sub64(t3, t3<<32, 0)
	a2, b = bits.Sub64(0, t3>>32, b)
	a3, b = bits.Sub64(0, t3<<32, b)
	a4, _ = bits.Sub64(t3, t3>>32, b)
	t4, b = bits.Add64(t4, a1, 0)
	t5, b = bits.Add64(t5, a2, b)
	t6, b = bits.Add64(t6, a3, b)
	t7, c = bits.Add64(t7, a4+c, b)

	r0, b := bits.Sub64(t4, p0, 0)
	r1, b := bits.Sub64(t5, p1, b)
	r2, b := bits.Sub64(t6, p2, b)
	r3, b := bits.Sub64(t7, p3, b)
	_, b = bits.Sub64(c, 0, b)
	keep := -b // all ones when t < p, so the subtraction is discarded
	z[0] = (t4 & keep) | (r0 &^ keep)
	z[1] = (t5 & keep) | (r1 &^ keep)
	z[2] = (t6 & keep) | (r2 &^ keep)
	z[3] = (t7 & keep) | (r3 &^ keep)
}

// mul512 returns the 512-bit product of x and y as eight little-endian limbs.
func mul512(x, y *[4]uint64) (t0, t1, t2, t3, t4, t5, t6, t7 uint64) {
	var h0, h1, h2, h3, l1, l2, l3, c uint64
	x0, x1, x2, x3 := x[0], x[1], x[2], x[3]
	y0, y1, y2, y3 := y[0], y[1], y[2], y[3]

	h0, t0 = bits.Mul64(x0, y0)
	h1, l1 = bits.Mul64(x0, y1)
	h2, l2 = bits.Mul64(x0, y2)
	h3, l3 = bits.Mul64(x0, y3)
	t1, c = bits.Add64(h0, l1, 0)
	t2, c = bits.Add64(h1, l2, c)
	t3, c = bits.Add64(h2, l3, c)
	t4 = h3 + c

	h0, l0 := bits.Mul64(x1, y0)
	h1, l1 = bits.Mul64(x1, y1)
	h2, l2 = bits.Mul64(x1, y2)
	h3, l3 = bits.Mul64(x1, y3)
	l1, c = bits.Add64(l1, h0, 0)
	l2, c = bits.Add64(l2, h1, c)
	l3, c = bits.Add64(l3, h2, c)
	h3 += c
	t1, c = bits.Add64(t1, l0, 0)
	t2, c = bits.Add64(t2, l1, c)
	t3, c = bits.Add64(t3, l2, c)
	t4, c = bits.Add64(t4, l3, c)
	t5 = h3 + c

	h0, l0 = bits.Mul64(x2, y0)
	h1, l1 = bits.Mul64(x2, y1)
	h2, l2 = bits.Mul64(x2, y2)
	h3, l3 = bits.Mul64(x2, y3)
	l1, c = bits.Add64(l1, h0, 0)
	l2, c = bits.Add64(l2, h1, c)
	l3, c = bits.Add64(l3, h2, c)
	h3 += c
	t2, c = bits.Add64(t2, l0, 0)
	t3, c = bits.Add64(t3, l1, c)
	t4, c = bits.Add64(t4, l2, c)
	t5, c = bits.Add64(t5, l3, c)
	t6 = h3 + c

	h0, l0 = bits.Mul64(x3, y0)
	h1, l1 = bits.Mul64(x3, y1)
	h2, l2 = bits.Mul64(x3, y2)
	h3, l3 = bits.Mul64(x3, y3)
	l1, c = bits.Add64(l1, h0, 0)
	l2, c = bits.Add64(l2, h1, c)
	l3, c = bits.Add64(l3, h2, c)
	h3 += c
	t3, c = bits.Add64(t3, l0, 0)
	t4, c = bits.Add64(t4, l1, c)
	t5, c = bits.Add64(t5, l2, c)
	t6, c = bits.Add64(t6, l3, c)
	t7 = h3 + c
	return
}

// sqr512 returns the 512-bit square of x; it needs 10 limb multiplications, not 16.
func sqr512(x *[4]uint64) (t0, t1, t2, t3, t4, t5, t6, t7 uint64) {
	var c uint64
	x0, x1, x2, x3 := x[0], x[1], x[2], x[3]

	// Cross products.
	h01, l01 := bits.Mul64(x0, x1)
	h02, l02 := bits.Mul64(x0, x2)
	h03, l03 := bits.Mul64(x0, x3)
	h12, l12 := bits.Mul64(x1, x2)
	h13, l13 := bits.Mul64(x1, x3)
	h23, l23 := bits.Mul64(x2, x3)

	t1 = l01
	t2, c = bits.Add64(h01, l02, 0)
	t3, c = bits.Add64(h02, l03, c)
	t4, c = bits.Add64(h03, l13, c)
	t5, c = bits.Add64(h13, l23, c)
	t6 = h23 + c
	t3, c = bits.Add64(t3, l12, 0)
	t4, c = bits.Add64(t4, h12, c)
	t5, c = bits.Add64(t5, 0, c)
	t6 += c

	// Double them.
	t7 = t6 >> 63
	t6 = t6<<1 | t5>>63
	t5 = t5<<1 | t4>>63
	t4 = t4<<1 | t3>>63
	t3 = t3<<1 | t2>>63
	t2 = t2<<1 | t1>>63
	t1 <<= 1

	// Add the diagonal.
	h0, l0 := bits.Mul64(x0, x0)
	h1, l1 := bits.Mul64(x1, x1)
	h2, l2 := bits.Mul64(x2, x2)
	h3, l3 := bits.Mul64(x3, x3)
	t0 = l0
	t1, c = bits.Add64(t1, h0, 0)
	t2, c = bits.Add64(t2, l1, c)
	t3, c = bits.Add64(t3, h1, c)
	t4, c = bits.Add64(t4, l2, c)
	t5, c = bits.Add64(t5, h2, c)
	t6, c = bits.Add64(t6, l3, c)
	t7 += h3 + c
	return
}

// feMul sets z = x*y*R^-1 mod p. At least one input must be below p; the other may be
// any 256-bit value.
func feMul(z, x, y *fe) {
	t0, t1, t2, t3, t4, t5, t6, t7 := mul512((*[4]uint64)(x), (*[4]uint64)(y))
	feMontReduce(z, t0, t1, t2, t3, t4, t5, t6, t7)
}

// feSqr sets z = x*x*R^-1 mod p for x below p.
func feSqr(z, x *fe) {
	t0, t1, t2, t3, t4, t5, t6, t7 := sqr512((*[4]uint64)(x))
	feMontReduce(z, t0, t1, t2, t3, t4, t5, t6, t7)
}

// feSqrN sets z to x squared n times (n >= 1).
func feSqrN(z, x *fe, n int) {
	feSqr(z, x)
	for i := 1; i < n; i++ {
		feSqr(z, z)
	}
}

// feAdd sets z = x + y mod p for reduced inputs.
func feAdd(z, x, y *fe) {
	s0, c := bits.Add64(x[0], y[0], 0)
	s1, c := bits.Add64(x[1], y[1], c)
	s2, c := bits.Add64(x[2], y[2], c)
	s3, c := bits.Add64(x[3], y[3], c)

	r0, b := bits.Sub64(s0, p0, 0)
	r1, b := bits.Sub64(s1, p1, b)
	r2, b := bits.Sub64(s2, p2, b)
	r3, b := bits.Sub64(s3, p3, b)
	_, b = bits.Sub64(c, 0, b)
	keep := -b
	z[0] = (s0 & keep) | (r0 &^ keep)
	z[1] = (s1 & keep) | (r1 &^ keep)
	z[2] = (s2 & keep) | (r2 &^ keep)
	z[3] = (s3 & keep) | (r3 &^ keep)
}

// feSub sets z = x - y mod p for reduced inputs.
func feSub(z, x, y *fe) {
	d0, b := bits.Sub64(x[0], y[0], 0)
	d1, b := bits.Sub64(x[1], y[1], b)
	d2, b := bits.Sub64(x[2], y[2], b)
	d3, b := bits.Sub64(x[3], y[3], b)

	mask := -b
	var c uint64
	z[0], c = bits.Add64(d0, p0&mask, 0)
	z[1], c = bits.Add64(d1, p1&mask, c)
	z[2], c = bits.Add64(d2, p2&mask, c)
	z[3], _ = bits.Add64(d3, p3&mask, c)
}

// feDouble sets z = 2*x mod p.
func feDouble(z, x *fe) { feAdd(z, x, x) }

// feNeg sets z = -x mod p.
func feNeg(z, x *fe) {
	var zero fe
	feSub(z, &zero, x)
}

// feSelect sets z to x when mask is all ones and leaves z unchanged when mask is zero.
func feSelect(z, x *fe, mask uint64) {
	z[0] = (z[0] &^ mask) | (x[0] & mask)
	z[1] = (z[1] &^ mask) | (x[1] & mask)
	z[2] = (z[2] &^ mask) | (x[2] & mask)
	z[3] = (z[3] &^ mask) | (x[3] & mask)
}

// feIsZeroMask returns all ones if x is zero and zero otherwise.
func feIsZeroMask(x *fe) uint64 {
	v := x[0] | x[1] | x[2] | x[3]
	return ((v | -v) >> 63) - 1
}

// feReduce returns x mod p. Any 256-bit value is below 2p, so one conditional
// subtraction is enough.
func feReduce(x *[4]uint64) fe {
	r0, b := bits.Sub64(x[0], p0, 0)
	r1, b := bits.Sub64(x[1], p1, b)
	r2, b := bits.Sub64(x[2], p2, b)
	r3, b := bits.Sub64(x[3], p3, b)
	keep := -b
	return fe{
		(x[0] & keep) | (r0 &^ keep),
		(x[1] & keep) | (r1 &^ keep),
		(x[2] & keep) | (r2 &^ keep),
		(x[3] & keep) | (r3 &^ keep),
	}
}

// feToMont sets z to the Montgomery form of the plain value x.
func feToMont(z *fe, x *[4]uint64) {
	feMul(z, (*fe)(x), &feRR)
}

// feFromMont returns the plain, fully reduced value of x.
func feFromMont(x *fe) [4]uint64 {
	var z fe
	feMontReduce(&z, x[0], x[1], x[2], x[3], 0, 0, 0, 0)
	return z
}

// feInvert sets z = x^-1 mod p, or zero if x is zero. It raises x to the fixed
// exponent p-2 with an addition chain (255 squarings, 14 multiplications).
//
// In binary p-2 is 31 ones, a zero, 128 ones, 32 zeros, 62 ones, then 01.
func feInvert(z, x *fe) {
	var x2, x3, x6, x12, x15, x30, x31, x32, t fe

	feSqr(&x2, x)
	feMul(&x2, &x2, x) // 2 ones
	feSqr(&x3, &x2)
	feMul(&x3, &x3, x) // 3 ones
	feSqrN(&x6, &x3, 3)
	feMul(&x6, &x6, &x3)
	feSqrN(&x12, &x6, 6)
	feMul(&x12, &x12, &x6)
	feSqrN(&x15, &x12, 3)
	feMul(&x15, &x15, &x3)
	feSqrN(&x30, &x15, 15)
	feMul(&x30, &x30, &x15)
	feSqr(&x31, &x30)
	feMul(&x31, &x31, x)
	feSqr(&x32, &x31)
	feMul(&x32, &x32, x)

	feSqr(&t, &x31) // the zero bit
	for i := 0; i < 4; i++ {
		feSqrN(&t, &t, 32)
		feMul(&t, &t, &x32)
	}
	feSqrN(&t, &t, 32) // the zeros
	feSqrN(&t, &t, 32)
	feMul(&t, &t, &x32)
	feSqrN(&t, &t, 30)
	feMul(&t, &t, &x30)
	feSqrN(&t, &t, 2)
	feMul(z, &t, x)
}
