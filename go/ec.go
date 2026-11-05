package smx

import (
	"math/bits"
	"sync"
)

// jacPoint is a point in Jacobian coordinates (x/z^2, y/z^3) with Montgomery-form
// coordinates. z == 0 represents the point at infinity.
type jacPoint struct {
	x, y, z fe
}

// affPoint is a finite point in affine coordinates with Montgomery-form coordinates.
type affPoint struct {
	x, y fe
}

// jacDouble sets r = 2*p using dbl-2001-b, specialised for a = -3 (3M + 5S). The
// point at infinity and points with y == 0 both produce z == 0.
func jacDouble(r, p *jacPoint) {
	var delta, gamma, beta, alpha, t, u, x3, y3, z3 fe

	feSqr(&delta, &p.z)
	feSqr(&gamma, &p.y)
	feMul(&beta, &p.x, &gamma)

	feSub(&t, &p.x, &delta)
	feAdd(&u, &p.x, &delta)
	feMul(&alpha, &t, &u)
	feDouble(&t, &alpha)
	feAdd(&alpha, &alpha, &t) // alpha = 3*(x-delta)*(x+delta)

	feDouble(&u, &beta)
	feDouble(&u, &u) // u = 4*beta
	feDouble(&t, &u) // t = 8*beta
	feSqr(&x3, &alpha)
	feSub(&x3, &x3, &t)

	feAdd(&z3, &p.y, &p.z)
	feSqr(&z3, &z3)
	feSub(&z3, &z3, &gamma)
	feSub(&z3, &z3, &delta)

	feSub(&u, &u, &x3)
	feMul(&y3, &alpha, &u)
	feSqr(&t, &gamma)
	feDouble(&t, &t)
	feDouble(&t, &t)
	feDouble(&t, &t) // t = 8*gamma^2
	feSub(&y3, &y3, &t)

	r.x, r.y, r.z = x3, y3, z3
}

// jacAddFormula sets r = p + q with add-1998-cmo-2 (12M + 4S) and returns the masks
// of h == 0 and s == 0. The formula is valid when neither input is at infinity and
// p != q; for p == -q it yields z == 0. No branch depends on the coordinates.
func jacAddFormula(r, p, q *jacPoint) (hZero, sZero uint64) {
	var z1z1, z2z2, u1, u2, s1, s2, h, hh, hhh, v, s, x3, y3, z3, t fe

	feSqr(&z1z1, &p.z)
	feSqr(&z2z2, &q.z)
	feMul(&u1, &p.x, &z2z2)
	feMul(&u2, &q.x, &z1z1)
	feMul(&s1, &p.y, &q.z)
	feMul(&s1, &s1, &z2z2)
	feMul(&s2, &q.y, &p.z)
	feMul(&s2, &s2, &z1z1)
	feSub(&h, &u2, &u1)
	feSub(&s, &s2, &s1)
	hZero, sZero = feIsZeroMask(&h), feIsZeroMask(&s)

	feSqr(&hh, &h)
	feMul(&hhh, &hh, &h)
	feMul(&v, &u1, &hh)
	feSqr(&x3, &s)
	feSub(&x3, &x3, &hhh)
	feDouble(&t, &v)
	feSub(&x3, &x3, &t)
	feSub(&t, &v, &x3)
	feMul(&y3, &s, &t)
	feMul(&t, &s1, &hhh)
	feSub(&y3, &y3, &t)
	feMul(&z3, &p.z, &q.z)
	feMul(&z3, &z3, &h)

	r.x, r.y, r.z = x3, y3, z3
	return hZero, sZero
}

// jacAddAffineFormula sets r = p + q for an affine q with madd-2004-hmv (8M + 3S).
// It has the same preconditions and results as jacAddFormula.
func jacAddAffineFormula(r, p *jacPoint, q *affPoint) (hZero, sZero uint64) {
	var z1z1, u2, s2, h, hh, hhh, v, s, x3, y3, z3, t fe

	feSqr(&z1z1, &p.z)
	feMul(&u2, &q.x, &z1z1)
	feMul(&s2, &q.y, &p.z)
	feMul(&s2, &s2, &z1z1)
	feSub(&h, &u2, &p.x)
	feSub(&s, &s2, &p.y)
	hZero, sZero = feIsZeroMask(&h), feIsZeroMask(&s)

	feSqr(&hh, &h)
	feMul(&hhh, &hh, &h)
	feMul(&v, &p.x, &hh)
	feSqr(&x3, &s)
	feSub(&x3, &x3, &hhh)
	feDouble(&t, &v)
	feSub(&x3, &x3, &t)
	feSub(&t, &v, &x3)
	feMul(&y3, &s, &t)
	feMul(&t, &p.y, &hhh)
	feSub(&y3, &y3, &t)
	feMul(&z3, &p.z, &h)

	r.x, r.y, r.z = x3, y3, z3
	return hZero, sZero
}

// jacAddVar sets r = p + q, handling every case. It branches on the inputs, so it is
// for public data only.
func jacAddVar(r, p, q *jacPoint) {
	if feIsZeroMask(&p.z) != 0 {
		*r = *q
		return
	}
	if feIsZeroMask(&q.z) != 0 {
		*r = *p
		return
	}
	var sum jacPoint
	hZero, sZero := jacAddFormula(&sum, p, q)
	if hZero != 0 && sZero != 0 {
		jacDouble(r, q)
		return
	}
	*r = sum
}

// jacAddAffineVar sets r = p + q for an affine q, handling every case. It branches on
// the inputs, so it is for public data only.
func jacAddAffineVar(r, p *jacPoint, q *affPoint) {
	if feIsZeroMask(&p.z) != 0 {
		r.x, r.y, r.z = q.x, q.y, feOne
		return
	}
	var sum jacPoint
	hZero, sZero := jacAddAffineFormula(&sum, p, q)
	if hZero != 0 && sZero != 0 {
		lifted := jacPoint{q.x, q.y, feOne}
		jacDouble(r, &lifted)
		return
	}
	*r = sum
}

// jacAddComplete sets r = p + q for every input, including p == q, without branching
// on the coordinates. It costs one extra doubling compared with jacAddConst.
func jacAddComplete(r, p, q *jacPoint) {
	var sum, twice jacPoint
	hZero, sZero := jacAddFormula(&sum, p, q)
	jacDouble(&twice, q)
	jacSelect(&sum, &twice, hZero&sZero)
	jacSelect(&sum, q, feIsZeroMask(&p.z))
	jacSelect(&sum, p, feIsZeroMask(&q.z))
	*r = sum
}

// jacAddConst sets r = p + q without branching on the coordinates. It handles p or q
// at infinity and p == -q, but not the doubling case p == q; the scalar multiplication
// loops below show where that cannot occur for points of the curve.
func jacAddConst(r, p, q *jacPoint) {
	var sum jacPoint
	jacAddFormula(&sum, p, q)
	jacSelect(&sum, q, feIsZeroMask(&p.z))
	jacSelect(&sum, p, feIsZeroMask(&q.z))
	*r = sum
}

// jacSelect sets r to p when mask is all ones and leaves r unchanged when mask is zero.
func jacSelect(r, p *jacPoint, mask uint64) {
	feSelect(&r.x, &p.x, mask)
	feSelect(&r.y, &p.y, mask)
	feSelect(&r.z, &p.z, mask)
}

// ctEqMask returns all ones if a == b and zero otherwise. Both must be below 2^63.
func ctEqMask(a, b uint64) uint64 {
	return -(((a ^ b) - 1) >> 63)
}

// boothDigit returns the magnitude and the sign mask (all ones when negative) of the
// signed window of width w whose lowest value bit is at position pos. The digit is
// taken from bits pos-1 to pos+w-1, so the digits of all windows add up to k.
// The recoding is branch free and pos is public.
func boothDigit(k *[4]uint64, pos, w uint) (magnitude, negative uint64) {
	var window uint64
	if pos == 0 {
		window = k[0] << 1
	} else {
		bit := pos - 1
		limb, shift := bit/64, bit%64
		if limb < 4 {
			window = k[limb] >> shift
			if shift != 0 && limb < 3 {
				window |= k[limb+1] << (64 - shift)
			}
		}
	}
	window &= 1<<(w+1) - 1

	// Top bit set: the digit is window - 2^(w+1), so the magnitude is its complement.
	negative = -(window >> w)
	complement := (1<<(w+1) - 1) - window
	v := (complement & negative) | (window &^ negative)
	return (v >> 1) + (v & 1), negative
}

const (
	varWindow    = 5
	varTableSize = 1 << (varWindow - 1)
	varWindows   = 52 // (256 + 1) bits in 5-bit signed windows
)

// jacScalarMult sets r = [k]p for a scalar below n, in constant time with respect to
// k: a fixed 5-bit signed window, and every lookup scans the whole table.
//
// The doubling case of the addition: for p of prime order n, the accumulator holds
// [m]p with m a non-negative multiple of 32 and the added point is [d]p with
// 1 <= |d| <= 16. Before the last window m is far below n, so m == d mod n would
// need m == d, which the multiple of 32 rules out. In the last window m + d == k, and
// k == n - 6 really does reach it: m == n - 3 and d == -3. So the last window, at a
// public position, uses the complete addition.
func jacScalarMult(r, p *jacPoint, k *[4]uint64) {
	var table [varTableSize]jacPoint
	table[0] = *p
	for i := 1; i < varTableSize; i++ {
		if i%2 == 1 {
			jacDouble(&table[i], &table[i/2])
		} else {
			// i+1 is odd: [i+1]p = [i]p + p with i >= 2, never a doubling.
			jacAddConst(&table[i], &table[i-1], p)
		}
	}

	acc := jacPoint{x: feOne, y: feOne}
	var entry jacPoint
	for w := varWindows - 1; w >= 0; w-- {
		if w != varWindows-1 {
			jacDouble(&acc, &acc)
			jacDouble(&acc, &acc)
			jacDouble(&acc, &acc)
			jacDouble(&acc, &acc)
			jacDouble(&acc, &acc)
		}
		magnitude, negative := boothDigit(k, uint(w)*varWindow, varWindow)

		lookupJacobian(&entry, &table, magnitude)
		var negY fe
		feNeg(&negY, &entry.y)
		feSelect(&entry.y, &negY, negative)
		if w == 0 {
			jacAddComplete(&acc, &acc, &entry)
		} else {
			jacAddConst(&acc, &acc, &entry)
		}
	}
	*r = acc
}

// lookupJacobian sets r to the entry for magnitude (1-based), or to the point at
// infinity for zero. It reads every entry, so the access pattern does not depend on it.
func lookupJacobian(r *jacPoint, table *[varTableSize]jacPoint, magnitude uint64) {
	var out jacPoint
	for i := range table {
		mask := ctEqMask(uint64(i+1), magnitude)
		e := &table[i]
		for j := range out.x {
			out.x[j] |= e.x[j] & mask
			out.y[j] |= e.y[j] & mask
			out.z[j] |= e.z[j] & mask
		}
	}
	*r = out
}

const (
	combWindow    = 6
	combTableSize = 1 << (combWindow - 1)
	combWindows   = 43 // (256 + 1) bits in 6-bit signed windows

	// baseWNAFWidth is the width of the wNAF digits used for the G term in verification.
	baseWNAFWidth = 8
	baseWNAFSize  = 1 << (baseWNAFWidth - 2)
)

// sm2BaseTables holds the affine multiples of G. combTable[i][j] is [(j+1)*2^(6i)]G,
// and wnafTable[j] is [2j+1]G. It is built once, on first use, in well under a
// millisecond, and takes about 92 KiB.
type sm2BaseTables struct {
	comb [combWindows][combTableSize]affPoint
	wnaf [baseWNAFSize]affPoint
}

var (
	baseTablesOnce sync.Once
	baseTablesPtr  *sm2BaseTables
)

func baseTables() *sm2BaseTables {
	baseTablesOnce.Do(func() { baseTablesPtr = newBaseTables() })
	return baseTablesPtr
}

func newBaseTables() *sm2BaseTables {
	const total = combWindows*combTableSize + baseWNAFSize
	points := make([]jacPoint, total)

	var gx, gy fe
	feToMont(&gx, &SM2_GX.value.limbs)
	feToMont(&gy, &SM2_GY.value.limbs)
	g := jacPoint{gx, gy, feOne}

	// Comb entries.
	base := g
	for i := 0; i < combWindows; i++ {
		row := points[i*combTableSize : (i+1)*combTableSize]
		row[0] = base
		for j := 1; j < combTableSize; j++ {
			jacAddVar(&row[j], &row[j-1], &base)
		}
		for s := 0; s < combWindow; s++ {
			jacDouble(&base, &base)
		}
	}

	// Odd multiples of G for the wNAF.
	wnaf := points[combWindows*combTableSize:]
	var g2 jacPoint
	jacDouble(&g2, &g)
	wnaf[0] = g
	for j := 1; j < baseWNAFSize; j++ {
		jacAddVar(&wnaf[j], &wnaf[j-1], &g2)
	}

	affine := batchToAffine(points)
	t := new(sm2BaseTables)
	for i := range t.comb {
		copy(t.comb[i][:], affine[i*combTableSize:(i+1)*combTableSize])
	}
	copy(t.wnaf[:], affine[combWindows*combTableSize:])
	return t
}

// batchToAffine converts finite points to affine form using a single inversion
// (Montgomery's trick). It is used only for public points.
func batchToAffine(points []jacPoint) []affPoint {
	products := make([]fe, len(points))
	acc := feOne
	for i := range points {
		products[i] = acc
		feMul(&acc, &acc, &points[i].z)
	}
	var inv fe
	feInvert(&inv, &acc)

	out := make([]affPoint, len(points))
	for i := len(points) - 1; i >= 0; i-- {
		var zInv, zz, zzz fe
		feMul(&zInv, &inv, &products[i])
		feMul(&inv, &inv, &points[i].z)
		feSqr(&zz, &zInv)
		feMul(&zzz, &zz, &zInv)
		feMul(&out[i].x, &points[i].x, &zz)
		feMul(&out[i].y, &points[i].y, &zzz)
	}
	return out
}

// lookupAffine sets r to the entry for magnitude (1-based), or to zeros for zero. It
// reads every entry, so the access pattern does not depend on it.
func lookupAffine(r *affPoint, row *[combTableSize]affPoint, magnitude uint64) {
	var x0, x1, x2, x3, y0, y1, y2, y3 uint64
	for i := range row {
		mask := ctEqMask(uint64(i+1), magnitude)
		e := &row[i]
		x0 |= e.x[0] & mask
		x1 |= e.x[1] & mask
		x2 |= e.x[2] & mask
		x3 |= e.x[3] & mask
		y0 |= e.y[0] & mask
		y1 |= e.y[1] & mask
		y2 |= e.y[2] & mask
		y3 |= e.y[3] & mask
	}
	r.x = fe{x0, x1, x2, x3}
	r.y = fe{y0, y1, y2, y3}
}

// jacScalarBaseMult sets r = [k]G for a scalar below n, in constant time with respect
// to k: signed 6-bit windows over the precomputed comb table, every lookup scanning
// the whole row.
//
// Why the doubling case cannot occur: the partial sum S of the lower windows satisfies
// |S| < 2^(6i) <= |D| for the window value D being added, so S != +-D as integers.
// They could only agree modulo n when |S| + |D| reaches n, which needs the top window
// with D = 2^256. S == D - n would then mean k = 2D - n >= 2^256, and S == n - D
// would mean k == n, both outside the allowed range.
func jacScalarBaseMult(r *jacPoint, k *[4]uint64) {
	tables := baseTables()
	acc := jacPoint{x: feOne, y: feOne}
	for w := 0; w < combWindows; w++ {
		magnitude, negative := boothDigit(k, uint(w)*combWindow, combWindow)

		var entry affPoint
		lookupAffine(&entry, &tables.comb[w], magnitude)
		var negY fe
		feNeg(&negY, &entry.y)
		feSelect(&entry.y, &negY, negative)

		var sum jacPoint
		jacAddAffineFormula(&sum, &acc, &entry)
		lifted := jacPoint{entry.x, entry.y, feOne}
		jacSelect(&sum, &lifted, feIsZeroMask(&acc.z))
		jacSelect(&sum, &acc, ctEqMask(0, magnitude))
		acc = sum
	}
	*r = acc
}

// wnafRecode writes the width-w non-adjacent form of k into digits (least significant
// first) and returns the number of digits used. Digits are odd and below 2^(w-1) in
// magnitude. It branches on k: public scalars only.
func wnafRecode(digits *[258]int16, k *[4]uint64, w uint) int {
	v := [5]uint64{k[0], k[1], k[2], k[3], 0}
	mask := uint64(1)<<w - 1
	half := int64(1) << (w - 1)
	length := 0
	for i := range digits {
		var d int64
		if v[0]&1 == 1 {
			d = int64(v[0] & mask)
			if d >= half {
				d -= 2 * half
			}
			// v -= d. A positive d only clears low bits; a negative d may carry.
			var c uint64
			v[0], c = bits.Add64(v[0], uint64(-d), 0)
			if d >= 0 {
				c = 0
			}
			v[1], c = bits.Add64(v[1], 0, c)
			v[2], c = bits.Add64(v[2], 0, c)
			v[3], c = bits.Add64(v[3], 0, c)
			v[4] += c
			length = i + 1
		}
		digits[i] = int16(d)
		v[0] = v[0]>>1 | v[1]<<63
		v[1] = v[1]>>1 | v[2]<<63
		v[2] = v[2]>>1 | v[3]<<63
		v[3] = v[3]>>1 | v[4]<<63
		v[4] >>= 1
	}
	return length
}

const varWNAFWidth = 5

// oddMultiples fills table with [1]p, [3]p, [5]p, ...
func oddMultiples(table *[1 << (varWNAFWidth - 2)]jacPoint, p *jacPoint) {
	var twice jacPoint
	jacDouble(&twice, p)
	table[0] = *p
	for i := 1; i < len(table); i++ {
		jacAddVar(&table[i], &table[i-1], &twice)
	}
}

// addWNAFDigit adds [d]p to acc for a signed odd digit, or nothing for zero.
func addWNAFDigit(acc *jacPoint, table *[1 << (varWNAFWidth - 2)]jacPoint, d int16) {
	if d > 0 {
		jacAddVar(acc, acc, &table[d>>1])
	} else if d < 0 {
		q := table[(-d)>>1]
		feNeg(&q.y, &q.y)
		jacAddVar(acc, acc, &q)
	}
}

// jacDoubleScalarMultVar sets r = [s]G + [t]p, using interleaved wNAF (Shamir's
// trick). It branches on the scalars and on the points, so both must be public, as they
// are in signature verification. A nil p omits the second term.
func jacDoubleScalarMultVar(r *jacPoint, s, t *[4]uint64, p *jacPoint) {
	tables := baseTables()

	var sDigits, tDigits [258]int16
	top := wnafRecode(&sDigits, s, baseWNAFWidth)

	var pTable [1 << (varWNAFWidth - 2)]jacPoint
	if p != nil {
		if n := wnafRecode(&tDigits, t, varWNAFWidth); n > top {
			top = n
		}
		oddMultiples(&pTable, p)
	}

	acc := jacPoint{x: feOne, y: feOne}
	for i := top - 1; i >= 0; i-- {
		jacDouble(&acc, &acc)
		if d := sDigits[i]; d > 0 {
			jacAddAffineVar(&acc, &acc, &tables.wnaf[d>>1])
		} else if d < 0 {
			q := tables.wnaf[(-d)>>1]
			feNeg(&q.y, &q.y)
			jacAddAffineVar(&acc, &acc, &q)
		}
		addWNAFDigit(&acc, &pTable, tDigits[i])
	}
	*r = acc
}

// jacScalarMultVar sets r = [k]p for a public scalar with a wNAF.
func jacScalarMultVar(r, p *jacPoint, k *[4]uint64) {
	var digits [258]int16
	top := wnafRecode(&digits, k, varWNAFWidth)

	var table [1 << (varWNAFWidth - 2)]jacPoint
	oddMultiples(&table, p)

	acc := jacPoint{x: feOne, y: feOne}
	for i := top - 1; i >= 0; i-- {
		jacDouble(&acc, &acc)
		addWNAFDigit(&acc, &table, digits[i])
	}
	*r = acc
}

// jacFromAffinePoint lifts a public point. The caller handles infinity.
func jacFromAffinePoint(p *ECPoint) jacPoint {
	var r jacPoint
	feToMont(&r.x, &p.X.value.limbs)
	feToMont(&r.y, &p.Y.value.limbs)
	r.z = feOne
	return r
}

// toAffinePoint converts to the public affine type. The only branch tests for the
// point at infinity, which reveals nothing for a scalar in [1, n-1].
func (p *jacPoint) toAffinePoint() ECPoint {
	if feIsZeroMask(&p.z) != 0 {
		return ECPointInfinity()
	}
	var zInv fe
	feInvert(&zInv, &p.z)
	return p.affineWithInverse(&zInv)
}

// affineWithInverse converts to affine form given z^-1.
func (p *jacPoint) affineWithInverse(zInv *fe) ECPoint {
	var zz, zzz, x, y fe
	feSqr(&zz, zInv)
	feMul(&zzz, &zz, zInv)
	feMul(&x, &p.x, &zz)
	feMul(&y, &p.y, &zzz)
	return ECPoint{
		X: FpElement{value: BigInt256{limbs: feFromMont(&x)}},
		Y: FpElement{value: BigInt256{limbs: feFromMont(&y)}},
	}
}

// pairToAffine converts two points with one shared inversion.
func pairToAffine(p, q *jacPoint) (ECPoint, ECPoint) {
	if feIsZeroMask(&p.z)|feIsZeroMask(&q.z) != 0 {
		return p.toAffinePoint(), q.toAffinePoint()
	}
	var product, inv, pInv, qInv fe
	feMul(&product, &p.z, &q.z)
	feInvert(&inv, &product)
	feMul(&pInv, &inv, &q.z)
	feMul(&qInv, &inv, &p.z)
	return p.affineWithInverse(&pInv), q.affineWithInverse(&qInv)
}
