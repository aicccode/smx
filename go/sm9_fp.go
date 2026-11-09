package smx

import "math/bits"

// SM9 base field Fq and scalar field (integers modulo the group order N).
//
// sm9Fp holds a value modulo the SM9 prime q in Montgomery form with R = 2^256, four
// little-endian limbs. q has no special shape, so reduction is the generic word-by-word
// Montgomery reduction. Every function here runs in time independent of the limb values:
// carries come from math/bits intrinsics and reductions use masks, never branches.
// Output parameters may alias inputs.
type sm9Fp [4]uint64

var (
	// sm9Q is the field prime q.
	sm9Q = [4]uint64{0xE56F9B27E351457D, 0x21F2934B1A7AEEDB, 0xD603AB4FF58EC745, 0xB640000002A3A6F1}
	// sm9N is the group order N, and sm9NMinus1 is N-1, the modulus of H1 and H2.
	sm9N       = [4]uint64{0xE56EE19CD69ECF25, 0x49F2934B18EA8BEE, 0xD603AB4FF58EC744, 0xB640000002A3A6F1}
	sm9NMinus1 = [4]uint64{0xE56EE19CD69ECF24, 0x49F2934B18EA8BEE, 0xD603AB4FF58EC744, 0xB640000002A3A6F1}
)

// The limbs of q, as constants for the unrolled Fq arithmetic.
const (
	sm9Q0 = 0xE56F9B27E351457D
	sm9Q1 = 0x21F2934B1A7AEEDB
	sm9Q2 = 0xD603AB4FF58EC745
	sm9Q3 = 0xB640000002A3A6F1
)

const (
	// sm9QInv and sm9NMontInv are -q^-1 and -N^-1 modulo 2^64.
	sm9QInv     = 0x892BC42C2F2EE42B
	sm9NMontInv = 0x1D02662351974B53
)

var (
	// sm9FpOne is 1 in Montgomery form (R mod q), sm9FpRR is R^2 mod q.
	sm9FpOne = sm9Fp{0x1A9064D81CAEBA83, 0xDE0D6CB4E5851124, 0x29FC54B00A7138BA, 0x49BFFFFFFD5C590E}
	sm9FpRR  = sm9Fp{0x27DEA312B417E2D2, 0x88F8105FAE1A5D3F, 0xE479B522D6706E7B, 0x2EA795A656F62FBD}
	// sm9FpB is the curve coefficient b = 5.
	sm9FpB = sm9Fp{0xB9F2C1E8C8C71995, 0x125DF8F246A377FC, 0x25E650D049188D1C, 0x043FFFFFED866F63}
	// sm9NRR is R^2 mod N.
	sm9NRR = [4]uint64{0x7598CD79CD750C35, 0xE4A08110BB6DAEAB, 0xBFEE4BAE7D78A1F9, 0x8894F5D163695D0E}
)

// sm9MontRound adds k*m to the five limbs starting at t0, with k chosen to cancel t0, and
// returns the four remaining limbs and the carry out of them.
func sm9MontRound(m *[4]uint64, mInv, t0, t1, t2, t3, t4 uint64) (r1, r2, r3, r4, carry uint64) {
	k := t0 * mInv
	var c, cc uint64

	hi, lo := bits.Mul64(k, m[0])
	_, c = bits.Add64(t0, lo, 0)
	h := hi + c

	hi, lo = bits.Mul64(k, m[1])
	lo, c = bits.Add64(lo, h, 0)
	r1, cc = bits.Add64(t1, lo, 0)
	h = hi + c + cc

	hi, lo = bits.Mul64(k, m[2])
	lo, c = bits.Add64(lo, h, 0)
	r2, cc = bits.Add64(t2, lo, 0)
	h = hi + c + cc

	hi, lo = bits.Mul64(k, m[3])
	lo, c = bits.Add64(lo, h, 0)
	r3, cc = bits.Add64(t3, lo, 0)
	h = hi + c + cc

	r4, carry = bits.Add64(t4, h, 0)
	return r1, r2, r3, r4, carry
}

// sm9MontReduce sets z to (t7..t0) / R mod m for an odd m above 2^255. The input must
// be below m*R, which keeps the result below 2m before the final conditional subtraction.
func sm9MontReduce(z *[4]uint64, m *[4]uint64, mInv uint64, t0, t1, t2, t3, t4, t5, t6, t7 uint64) {
	var c, c2 uint64
	t1, t2, t3, t4, c = sm9MontRound(m, mInv, t0, t1, t2, t3, t4)
	t2, t3, t4, t5, c2 = sm9MontRound(m, mInv, t1, t2, t3, t4, t5)
	t5, c = bits.Add64(t5, c, 0)
	c += c2
	t3, t4, t5, t6, c2 = sm9MontRound(m, mInv, t2, t3, t4, t5, t6)
	t6, c = bits.Add64(t6, c, 0)
	c += c2
	t4, t5, t6, t7, c2 = sm9MontRound(m, mInv, t3, t4, t5, t6, t7)
	t7, c = bits.Add64(t7, c, 0)
	c += c2
	sm9CondSub(z, m, t4, t5, t6, t7, c)
}

// sm9CondSub sets z to (c, x3..x0) minus m if that is not negative, and to x otherwise.
func sm9CondSub(z, m *[4]uint64, x0, x1, x2, x3, c uint64) {
	r0, b := bits.Sub64(x0, m[0], 0)
	r1, b := bits.Sub64(x1, m[1], b)
	r2, b := bits.Sub64(x2, m[2], b)
	r3, b := bits.Sub64(x3, m[3], b)
	_, b = bits.Sub64(c, 0, b)
	keep := -b // all ones when the value is below m
	z[0] = (x0 & keep) | (r0 &^ keep)
	z[1] = (x1 & keep) | (r1 &^ keep)
	z[2] = (x2 & keep) | (r2 &^ keep)
	z[3] = (x3 & keep) | (r3 &^ keep)
}

// sm9AddMod sets z = x + y mod m for x, y below m.
func sm9AddMod(z, x, y, m *[4]uint64) {
	s0, c := bits.Add64(x[0], y[0], 0)
	s1, c := bits.Add64(x[1], y[1], c)
	s2, c := bits.Add64(x[2], y[2], c)
	s3, c := bits.Add64(x[3], y[3], c)
	sm9CondSub(z, m, s0, s1, s2, s3, c)
}

// sm9SubMod sets z = x - y mod m for x, y below m.
func sm9SubMod(z, x, y, m *[4]uint64) {
	d0, b := bits.Sub64(x[0], y[0], 0)
	d1, b := bits.Sub64(x[1], y[1], b)
	d2, b := bits.Sub64(x[2], y[2], b)
	d3, b := bits.Sub64(x[3], y[3], b)
	mask := -b
	var c uint64
	z[0], c = bits.Add64(d0, m[0]&mask, 0)
	z[1], c = bits.Add64(d1, m[1]&mask, c)
	z[2], c = bits.Add64(d2, m[2]&mask, c)
	z[3], _ = bits.Add64(d3, m[3]&mask, c)
}

// sm9LessThan reports, in constant time, whether x < m, as 1 or 0.
func sm9LessThan(x, m *[4]uint64) uint64 {
	_, b := bits.Sub64(x[0], m[0], 0)
	_, b = bits.Sub64(x[1], m[1], b)
	_, b = bits.Sub64(x[2], m[2], b)
	_, b = bits.Sub64(x[3], m[3], b)
	return b
}

// --- Fq ---

// sm9FpMontReduce sets z to (t7..t0) / R mod q, fully unrolled with the constants of q.
// The input must be below q*R.
func sm9FpMontReduce(z *sm9Fp, t0, t1, t2, t3, t4, t5, t6, t7 uint64) {
	var k, hi, lo, c, cc, h, top, c2 uint64
	k = t0 * sm9QInv
	hi, lo = bits.Mul64(k, sm9Q0)
	_, c = bits.Add64(t0, lo, 0)
	h = hi + c
	hi, lo = bits.Mul64(k, sm9Q1)
	lo, c = bits.Add64(lo, h, 0)
	t1, cc = bits.Add64(t1, lo, 0)
	h = hi + c + cc
	hi, lo = bits.Mul64(k, sm9Q2)
	lo, c = bits.Add64(lo, h, 0)
	t2, cc = bits.Add64(t2, lo, 0)
	h = hi + c + cc
	hi, lo = bits.Mul64(k, sm9Q3)
	lo, c = bits.Add64(lo, h, 0)
	t3, cc = bits.Add64(t3, lo, 0)
	h = hi + c + cc
	t4, top = bits.Add64(t4, h, 0)
	k = t1 * sm9QInv
	hi, lo = bits.Mul64(k, sm9Q0)
	_, c = bits.Add64(t1, lo, 0)
	h = hi + c
	hi, lo = bits.Mul64(k, sm9Q1)
	lo, c = bits.Add64(lo, h, 0)
	t2, cc = bits.Add64(t2, lo, 0)
	h = hi + c + cc
	hi, lo = bits.Mul64(k, sm9Q2)
	lo, c = bits.Add64(lo, h, 0)
	t3, cc = bits.Add64(t3, lo, 0)
	h = hi + c + cc
	hi, lo = bits.Mul64(k, sm9Q3)
	lo, c = bits.Add64(lo, h, 0)
	t4, cc = bits.Add64(t4, lo, 0)
	h = hi + c + cc
	t5, c2 = bits.Add64(t5, h, 0)
	t5, c = bits.Add64(t5, top, 0)
	top = c + c2
	k = t2 * sm9QInv
	hi, lo = bits.Mul64(k, sm9Q0)
	_, c = bits.Add64(t2, lo, 0)
	h = hi + c
	hi, lo = bits.Mul64(k, sm9Q1)
	lo, c = bits.Add64(lo, h, 0)
	t3, cc = bits.Add64(t3, lo, 0)
	h = hi + c + cc
	hi, lo = bits.Mul64(k, sm9Q2)
	lo, c = bits.Add64(lo, h, 0)
	t4, cc = bits.Add64(t4, lo, 0)
	h = hi + c + cc
	hi, lo = bits.Mul64(k, sm9Q3)
	lo, c = bits.Add64(lo, h, 0)
	t5, cc = bits.Add64(t5, lo, 0)
	h = hi + c + cc
	t6, c2 = bits.Add64(t6, h, 0)
	t6, c = bits.Add64(t6, top, 0)
	top = c + c2
	k = t3 * sm9QInv
	hi, lo = bits.Mul64(k, sm9Q0)
	_, c = bits.Add64(t3, lo, 0)
	h = hi + c
	hi, lo = bits.Mul64(k, sm9Q1)
	lo, c = bits.Add64(lo, h, 0)
	t4, cc = bits.Add64(t4, lo, 0)
	h = hi + c + cc
	hi, lo = bits.Mul64(k, sm9Q2)
	lo, c = bits.Add64(lo, h, 0)
	t5, cc = bits.Add64(t5, lo, 0)
	h = hi + c + cc
	hi, lo = bits.Mul64(k, sm9Q3)
	lo, c = bits.Add64(lo, h, 0)
	t6, cc = bits.Add64(t6, lo, 0)
	h = hi + c + cc
	t7, c2 = bits.Add64(t7, h, 0)
	t7, c = bits.Add64(t7, top, 0)
	top = c + c2
	r0, b := bits.Sub64(t4, sm9Q0, 0)
	r1, b := bits.Sub64(t5, sm9Q1, b)
	r2, b := bits.Sub64(t6, sm9Q2, b)
	r3, b := bits.Sub64(t7, sm9Q3, b)
	_, b = bits.Sub64(top, 0, b)
	keep := -b
	z[0] = (t4 & keep) | (r0 &^ keep)
	z[1] = (t5 & keep) | (r1 &^ keep)
	z[2] = (t6 & keep) | (r2 &^ keep)
	z[3] = (t7 & keep) | (r3 &^ keep)
}

func sm9FpMul(z, x, y *sm9Fp) {
	t0, t1, t2, t3, t4, t5, t6, t7 := mul512((*[4]uint64)(x), (*[4]uint64)(y))
	sm9FpMontReduce(z, t0, t1, t2, t3, t4, t5, t6, t7)
}

func sm9FpSqr(z, x *sm9Fp) {
	t0, t1, t2, t3, t4, t5, t6, t7 := sqr512((*[4]uint64)(x))
	sm9FpMontReduce(z, t0, t1, t2, t3, t4, t5, t6, t7)
}

// sm9FpAdd sets z = x + y mod q for reduced inputs.
func sm9FpAdd(z, x, y *sm9Fp) {
	s0, c := bits.Add64(x[0], y[0], 0)
	s1, c := bits.Add64(x[1], y[1], c)
	s2, c := bits.Add64(x[2], y[2], c)
	s3, c := bits.Add64(x[3], y[3], c)
	r0, b := bits.Sub64(s0, sm9Q0, 0)
	r1, b := bits.Sub64(s1, sm9Q1, b)
	r2, b := bits.Sub64(s2, sm9Q2, b)
	r3, b := bits.Sub64(s3, sm9Q3, b)
	_, b = bits.Sub64(c, 0, b)
	keep := -b
	z[0] = (s0 & keep) | (r0 &^ keep)
	z[1] = (s1 & keep) | (r1 &^ keep)
	z[2] = (s2 & keep) | (r2 &^ keep)
	z[3] = (s3 & keep) | (r3 &^ keep)
}

// sm9FpSub sets z = x - y mod q for reduced inputs.
func sm9FpSub(z, x, y *sm9Fp) {
	d0, b := bits.Sub64(x[0], y[0], 0)
	d1, b := bits.Sub64(x[1], y[1], b)
	d2, b := bits.Sub64(x[2], y[2], b)
	d3, b := bits.Sub64(x[3], y[3], b)
	mask := -b
	var c uint64
	z[0], c = bits.Add64(d0, sm9Q0&mask, 0)
	z[1], c = bits.Add64(d1, sm9Q1&mask, c)
	z[2], c = bits.Add64(d2, sm9Q2&mask, c)
	z[3], _ = bits.Add64(d3, sm9Q3&mask, c)
}

func sm9FpDouble(z, x *sm9Fp) { sm9FpAdd(z, x, x) }

func sm9FpNeg(z, x *sm9Fp) {
	var zero sm9Fp
	sm9FpSub(z, &zero, x)
}

// sm9FpSelect sets z to x when mask is all ones and leaves z unchanged when it is zero.
func sm9FpSelect(z, x *sm9Fp, mask uint64) {
	z[0] = (z[0] &^ mask) | (x[0] & mask)
	z[1] = (z[1] &^ mask) | (x[1] & mask)
	z[2] = (z[2] &^ mask) | (x[2] & mask)
	z[3] = (z[3] &^ mask) | (x[3] & mask)
}

// sm9FpIsZeroMask returns all ones if x is zero and zero otherwise.
func sm9FpIsZeroMask(x *sm9Fp) uint64 {
	v := x[0] | x[1] | x[2] | x[3]
	return ((v | -v) >> 63) - 1
}

// sm9FpEqualMask returns all ones if x == y and zero otherwise.
func sm9FpEqualMask(x, y *sm9Fp) uint64 {
	d := sm9Fp{x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]}
	return sm9FpIsZeroMask(&d)
}

// sm9FpToMont sets z to the Montgomery form of the plain value x, which must be below q.
func sm9FpToMont(z *sm9Fp, x *[4]uint64) {
	sm9FpMul(z, (*sm9Fp)(x), &sm9FpRR)
}

// sm9FpFromMont returns the plain value of x.
func sm9FpFromMont(x *sm9Fp) [4]uint64 {
	var z sm9Fp
	sm9FpMontReduce(&z, x[0], x[1], x[2], x[3], 0, 0, 0, 0)
	return z
}

// sm9FpSetBytes decodes 32 big-endian bytes into Montgomery form and reports whether the
// value was below q.
func sm9FpSetBytes(z *sm9Fp, b []byte) bool {
	v := BigInt256FromBEBytes(b[:32]).limbs
	ok := sm9LessThan(&v, &sm9Q) == 1
	sm9FpToMont(z, &v)
	return ok
}

// sm9FpPutBytes writes the 32-byte big-endian encoding of x to out.
func sm9FpPutBytes(out []byte, x *sm9Fp) {
	v := sm9FpFromMont(x)
	putLimbsBE((*[32]byte)(out[:32]), &v)
}

// sm9PowWindow4 computes base^exp with a fixed 4-bit window over a public exponent.
// mul and sqr work in the Montgomery domain of the caller; one is its unit.
func sm9PowWindow4(z, base *[4]uint64, exp *[4]uint64, one *[4]uint64,
	mul func(z, x, y *[4]uint64), sqr func(z, x *[4]uint64)) {
	var table [16][4]uint64
	table[0] = *one
	table[1] = *base
	for i := 2; i < 16; i++ {
		mul(&table[i], &table[i-1], base)
	}
	t := *one
	for i := 252; i >= 0; i -= 4 {
		sqr(&t, &t)
		sqr(&t, &t)
		sqr(&t, &t)
		sqr(&t, &t)
		// The exponent is public, so indexing by its digits leaks nothing.
		mul(&t, &t, &table[(exp[i/64]>>(uint(i)%64))&0xF])
	}
	*z = t
}

func sm9FpMulLimbs(z, x, y *[4]uint64) { sm9FpMul((*sm9Fp)(z), (*sm9Fp)(x), (*sm9Fp)(y)) }
func sm9FpSqrLimbs(z, x *[4]uint64)    { sm9FpSqr((*sm9Fp)(z), (*sm9Fp)(x)) }

// sm9FpInv sets z = x^-1, or zero for x == 0, as x^(q-2) with a public exponent.
func sm9FpInv(z, x *sm9Fp) {
	exp := sm9Q
	exp[0] -= 2
	sm9PowWindow4((*[4]uint64)(z), (*[4]uint64)(x), &exp, (*[4]uint64)(&sm9FpOne), sm9FpMulLimbs, sm9FpSqrLimbs)
}

// --- integers modulo N ---

// sm9NMontMul sets z = x*y/R mod N. One input must be below N.
func sm9NMontMul(z, x, y *[4]uint64) {
	t0, t1, t2, t3, t4, t5, t6, t7 := mul512(x, y)
	sm9MontReduce(z, &sm9N, sm9NMontInv, t0, t1, t2, t3, t4, t5, t6, t7)
}

func sm9NMontSqr(z, x *[4]uint64) {
	t0, t1, t2, t3, t4, t5, t6, t7 := sqr512(x)
	sm9MontReduce(z, &sm9N, sm9NMontInv, t0, t1, t2, t3, t4, t5, t6, t7)
}

// sm9NMul sets z = x*y mod N for plain values below N.
func sm9NMul(z, x, y *[4]uint64) {
	var t [4]uint64
	sm9NMontMul(&t, x, y)
	sm9NMontMul(z, &t, &sm9NRR)
}

// sm9NInv sets z = x^-1 mod N for a plain x below N, or zero for x == 0. The exponent
// N-2 is public and x may be secret: every step is a fixed multiplication.
func sm9NInv(z, x *[4]uint64) {
	var xm, oneM [4]uint64
	sm9NMontMul(&xm, x, &sm9NRR)
	one := [4]uint64{1}
	sm9NMontMul(&oneM, &one, &sm9NRR)
	exp := sm9N
	exp[0] -= 2
	var t [4]uint64
	sm9PowWindow4(&t, &xm, &exp, &oneM, sm9NMontMul, sm9NMontSqr)
	sm9MontReduce(z, &sm9N, sm9NMontInv, t[0], t[1], t[2], t[3], 0, 0, 0, 0)
	wipeLimbs(&xm)
	wipeLimbs(&t)
}

func sm9NAdd(z, x, y *[4]uint64) { sm9AddMod(z, x, y, &sm9N) }
func sm9NSub(z, x, y *[4]uint64) { sm9SubMod(z, x, y, &sm9N) }

// sm9NInRange reports, in constant time, whether k is in [1, N-1].
func sm9NInRange(k *[4]uint64) bool {
	v := k[0] | k[1] | k[2] | k[3]
	nonZero := (v | -v) >> 63
	return sm9LessThan(k, &sm9N)&nonZero == 1
}

// sm9IsZero reports, in constant time, whether k is zero.
func sm9IsZero(k *[4]uint64) bool {
	v := k[0] | k[1] | k[2] | k[3]
	return (v|-v)>>63 == 0
}

// sm9HashReduce returns (ha mod (N-1)) + 1 for the 40-byte big-endian ha, by binary
// long division with masked subtractions. ha is often derived from secrets (the signing
// w), so the work does not depend on its value.
func sm9HashReduce(ha *[40]byte) [4]uint64 {
	m := &sm9NMinus1
	var r [4]uint64
	for _, byt := range ha {
		for bit := 7; bit >= 0; bit-- {
			// r = 2r + bit, which can reach 2^257 - 1, then subtract m if it fits.
			top := r[3] >> 63
			r[3] = r[3]<<1 | r[2]>>63
			r[2] = r[2]<<1 | r[1]>>63
			r[1] = r[1]<<1 | r[0]>>63
			r[0] = r[0]<<1 | uint64(byt>>uint(bit))&1
			sm9CondSub(&r, m, r[0], r[1], r[2], r[3], top)
		}
	}
	one := [4]uint64{1}
	var out [4]uint64
	var c uint64
	out[0], c = bits.Add64(r[0], one[0], 0)
	out[1], c = bits.Add64(r[1], 0, c)
	out[2], c = bits.Add64(r[2], 0, c)
	out[3], _ = bits.Add64(r[3], 0, c)
	return out
}
