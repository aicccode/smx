package smx

import "math/bits"

// Arithmetic modulo the SM2 group order n, in Montgomery form with R = 2^256.
// Everything here is constant time with respect to the limb values, because the
// private key and the signing nonce pass through it. The exponent in
// scalarInvert is the public constant n-2.
const (
	n0 = 0x53BBF40939D54123
	n1 = 0x7203DF6B21C6052B
	n2 = 0xFFFFFFFFFFFFFFFF
	n3 = 0xFFFFFFFEFFFFFFFF

	// nInv is -n^-1 mod 2^64.
	nInv = 0x327F9E8872350975
)

// scalarRR is R^2 mod n.
var scalarRR = [4]uint64{0x901192AF7C114F20, 0x3464504ADE6FA2FA, 0x620FC84C3AFFE0D4, 0x1EB5E412A22B3D3B}

// scalarMontRound adds q*n to the five limbs starting at t0, with q chosen to cancel
// t0, and returns the four remaining limbs and the carry out of them.
func scalarMontRound(t0, t1, t2, t3, t4 uint64) (r1, r2, r3, r4, carry uint64) {
	q := t0 * nInv
	var c, cc uint64

	hi, lo := bits.Mul64(q, n0)
	_, c = bits.Add64(t0, lo, 0)
	k := hi + c

	hi, lo = bits.Mul64(q, n1)
	lo, c = bits.Add64(lo, k, 0)
	r1, cc = bits.Add64(t1, lo, 0)
	k = hi + c + cc

	hi, lo = bits.Mul64(q, n2)
	lo, c = bits.Add64(lo, k, 0)
	r2, cc = bits.Add64(t2, lo, 0)
	k = hi + c + cc

	hi, lo = bits.Mul64(q, n3)
	lo, c = bits.Add64(lo, k, 0)
	r3, cc = bits.Add64(t3, lo, 0)
	k = hi + c + cc

	r4, carry = bits.Add64(t4, k, 0)
	return r1, r2, r3, r4, carry
}

// scalarMontReduce sets z to (t7..t0) / R mod n. The input must be below n*R.
func scalarMontReduce(z *[4]uint64, t0, t1, t2, t3, t4, t5, t6, t7 uint64) {
	var c, c2 uint64
	t1, t2, t3, t4, c = scalarMontRound(t0, t1, t2, t3, t4)
	t2, t3, t4, t5, c2 = scalarMontRound(t1, t2, t3, t4, t5)
	t5, c = bits.Add64(t5, c, 0)
	c += c2
	t3, t4, t5, t6, c2 = scalarMontRound(t2, t3, t4, t5, t6)
	t6, c = bits.Add64(t6, c, 0)
	c += c2
	t4, t5, t6, t7, c2 = scalarMontRound(t3, t4, t5, t6, t7)
	t7, c = bits.Add64(t7, c, 0)
	c += c2

	r0, b := bits.Sub64(t4, n0, 0)
	r1, b := bits.Sub64(t5, n1, b)
	r2, b := bits.Sub64(t6, n2, b)
	r3, b := bits.Sub64(t7, n3, b)
	_, b = bits.Sub64(c, 0, b)
	keep := -b
	z[0] = (t4 & keep) | (r0 &^ keep)
	z[1] = (t5 & keep) | (r1 &^ keep)
	z[2] = (t6 & keep) | (r2 &^ keep)
	z[3] = (t7 & keep) | (r3 &^ keep)
}

// scalarMontMul sets z = x*y*R^-1 mod n. At least one input must be below n; the other
// may be any 256-bit value.
func scalarMontMul(z, x, y *[4]uint64) {
	t0, t1, t2, t3, t4, t5, t6, t7 := mul512(x, y)
	scalarMontReduce(z, t0, t1, t2, t3, t4, t5, t6, t7)
}

// scalarMontSqr sets z = x*x*R^-1 mod n for x below n.
func scalarMontSqr(z, x *[4]uint64) {
	t0, t1, t2, t3, t4, t5, t6, t7 := sqr512(x)
	scalarMontReduce(z, t0, t1, t2, t3, t4, t5, t6, t7)
}

// scalarMul sets z = x*y mod n for plain (non-Montgomery) values of any size below 2^256.
func scalarMul(z, x, y *[4]uint64) {
	reduced := scalarReduce(x)
	var t [4]uint64
	scalarMontMul(&t, &reduced, y)
	scalarMontMul(z, &t, &scalarRR)
}

// scalarInvert sets z = x^-1 mod n for a plain value x, or zero if x is a multiple of n.
// It uses a fixed 4-bit window over the public exponent n-2.
func scalarInvert(z, x *[4]uint64) {
	var table [16][4]uint64
	scalarMontMul(&table[1], x, &scalarRR)
	for i := 2; i < 16; i++ {
		scalarMontMul(&table[i], &table[i-1], &table[1])
	}

	exp := [4]uint64{n0 - 2, n1, n2, n3}
	t := table[exp[3]>>60]
	for i := 251; i >= 0; i -= 4 {
		scalarMontSqr(&t, &t)
		scalarMontSqr(&t, &t)
		scalarMontSqr(&t, &t)
		scalarMontSqr(&t, &t)
		window := (exp[i/64] >> (uint(i%64) - 3)) & 0xF
		if window != 0 {
			scalarMontMul(&t, &t, &table[window])
		}
	}
	// Leave Montgomery form.
	scalarMontReduce(z, t[0], t[1], t[2], t[3], 0, 0, 0, 0)
}

// scalarReduce returns k mod n in constant time. Any 256-bit value is below 2n, so
// one conditional subtraction is enough.
func scalarReduce(k *[4]uint64) [4]uint64 {
	r0, b := bits.Sub64(k[0], n0, 0)
	r1, b := bits.Sub64(k[1], n1, b)
	r2, b := bits.Sub64(k[2], n2, b)
	r3, b := bits.Sub64(k[3], n3, b)
	keep := -b
	return [4]uint64{
		(k[0] & keep) | (r0 &^ keep),
		(k[1] & keep) | (r1 &^ keep),
		(k[2] & keep) | (r2 &^ keep),
		(k[3] & keep) | (r3 &^ keep),
	}
}

// scalarInRange reports, in constant time, whether k is in [1, n-1].
func scalarInRange(k *[4]uint64) bool {
	_, b := bits.Sub64(k[0], n0, 0)
	_, b = bits.Sub64(k[1], n1, b)
	_, b = bits.Sub64(k[2], n2, b)
	_, b = bits.Sub64(k[3], n3, b)
	v := k[0] | k[1] | k[2] | k[3]
	nonZero := (v | -v) >> 63
	return b&nonZero == 1
}

// privateKeyInRange reports, in constant time, whether k is in [1, n-2], the range of
// valid SM2 private keys. At n-1 the signing formula would need the inverse of d+1 = n.
func privateKeyInRange(k *[4]uint64) bool {
	_, b := bits.Sub64(k[0], n0-1, 0)
	_, b = bits.Sub64(k[1], n1, b)
	_, b = bits.Sub64(k[2], n2, b)
	_, b = bits.Sub64(k[3], n3, b)
	v := k[0] | k[1] | k[2] | k[3]
	nonZero := (v | -v) >> 63
	return b&nonZero == 1
}

// limbsEqual reports, in constant time, whether a == b.
func limbsEqual(a, b *[4]uint64) bool {
	v := (a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3])
	return ((v|-v)>>63)^1 == 1
}
