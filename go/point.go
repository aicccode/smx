package smx

import "math/bits"

// SM2 curve constants. These variables are for reading only: the library never reads
// them, so changing one cannot alter its behavior.
var (
	// SM2_A is the curve coefficient a = p - 3.
	SM2_A = FpElement{value: BigInt256{limbs: [4]uint64{
		0xFFFFFFFFFFFFFFFC, 0xFFFFFFFF00000000,
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF,
	}}}

	// SM2_B is the curve coefficient b.
	SM2_B = FpElement{value: BigInt256{limbs: [4]uint64{
		0xDDBCBD414D940E93, 0xF39789F515AB8F92,
		0x4D5A9E4BCF6509A7, 0x28E9FA9E9D9F5E34,
	}}}

	// SM2_GX is the x coordinate of the generator.
	SM2_GX = FpElement{value: BigInt256{limbs: [4]uint64{
		0x715A4589334C74C7, 0x8FE30BBFF2660BE1,
		0x5F9904466A39C994, 0x32C4AE2C1F198119,
	}}}

	// SM2_GY is the y coordinate of the generator.
	SM2_GY = FpElement{value: BigInt256{limbs: [4]uint64{
		0x02DF32E52139F0A0, 0xD0A9877CC62A4740,
		0x59BDCEE36B692153, 0xBC3736A2F4F6779C,
	}}}

	// SM2_N is the order of the generator.
	SM2_N = BigInt256{limbs: [4]uint64{
		0x53BBF40939D54123, 0x7203DF6B21C6052B,
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF,
	}}
)

// ECPoint is an affine point on the SM2 curve.
type ECPoint struct {
	X, Y     FpElement
	Infinity bool
}

// Private copies of the curve constants, the ones the library uses.
var (
	curveN  = [4]uint64{n0, n1, n2, n3}
	curveGX = [4]uint64{0x715A4589334C74C7, 0x8FE30BBFF2660BE1, 0x5F9904466A39C994, 0x32C4AE2C1F198119}
	curveGY = [4]uint64{0x02DF32E52139F0A0, 0xD0A9877CC62A4740, 0x59BDCEE36B692153, 0xBC3736A2F4F6779C}
)

// NewECPoint returns the finite point (x, y). It does not check that the point is on
// the curve; every operation that uses a secret on a point does.
func NewECPoint(x, y FpElement) ECPoint {
	return ECPoint{X: x, Y: y}
}

// ECPointInfinity returns the point at infinity.
func ECPointInfinity() ECPoint {
	return ECPoint{Infinity: true}
}

// ECPointGenerator returns the curve generator G.
func ECPointGenerator() ECPoint {
	return ECPoint{X: FpElement{BigInt256{limbs: curveGX}}, Y: FpElement{BigInt256{limbs: curveGY}}}
}

// ECPointFromHex returns the point with the given coordinates, each exactly 64 hex
// digits and below p. This signature cannot report failure, so anything else, or a
// point off the curve, gives the point at infinity, which every key operation rejects.
func ECPointFromHex(xHex, yHex string) ECPoint {
	if len(xHex) != 64 || len(yHex) != 64 {
		return ECPointInfinity()
	}
	var buf [65]byte
	buf[0] = 0x04
	if !decodeHexInto(buf[1:33], xHex) || !decodeHexInto(buf[33:65], yHex) {
		return ECPointInfinity()
	}
	return ECPointFromEncoded(buf[:])
}

// parseEncodedPoint decodes exactly 04||x||y, checking that x and y are below p and that
// the point is on the curve. Nothing is reduced or normalized.
func parseEncodedPoint(data []byte) (ECPoint, bool) {
	if len(data) != 65 || data[0] != 0x04 {
		return ECPointInfinity(), false
	}
	x := BigInt256FromBEBytes(data[1:33])
	y := BigInt256FromBEBytes(data[33:65])
	if !limbsBelowP(&x.limbs) || !limbsBelowP(&y.limbs) {
		return ECPointInfinity(), false
	}
	p := ECPoint{X: FpElement{x}, Y: FpElement{y}}
	if !p.IsOnCurve() {
		return ECPointInfinity(), false
	}
	return p, true
}

// ECPointFromEncoded decodes from 04||x||y format. This signature cannot report failure,
// so invalid input gives the point at infinity, which every key operation rejects. Use
// SM2ParsePublicKey to get an error instead.
func ECPointFromEncoded(data []byte) ECPoint {
	p, _ := parseEncodedPoint(data)
	return p
}

// ECPointFromHexEncoded decodes from a hex string of 04||x||y, exactly 130 digits. This
// signature cannot report failure, so invalid input gives the point at infinity, which
// every key operation rejects. Use SM2ParsePublicKey to get an error instead.
func ECPointFromHexEncoded(s string) ECPoint {
	p, _ := parseHexPoint(s)
	return p
}

func parseHexPoint(s string) (ECPoint, bool) {
	if len(s) != 130 {
		return ECPointInfinity(), false
	}
	var buf [65]byte
	if !decodeHexInto(buf[:], s) {
		return ECPointInfinity(), false
	}
	return parseEncodedPoint(buf[:])
}

// ToEncoded encodes the point as 04||x||y bytes.
func (p ECPoint) ToEncoded() []byte {
	if p.Infinity {
		return []byte{0x00}
	}
	result := make([]byte, 65)
	p.encodeTo((*[65]byte)(result))
	return result
}

// encodeTo writes 04||x||y of a finite point.
func (p *ECPoint) encodeTo(out *[65]byte) {
	out[0] = 0x04
	putLimbsBE((*[32]byte)(out[1:33]), &p.X.value.limbs)
	putLimbsBE((*[32]byte)(out[33:65]), &p.Y.value.limbs)
}

// ToHexEncoded encodes the point as a lowercase hex string.
func (p ECPoint) ToHexEncoded() string {
	if p.Infinity {
		return "00"
	}
	var buf [65]byte
	p.encodeTo(&buf)
	return bytesToHex(buf[:])
}

// Negate returns -p.
func (p ECPoint) Negate() ECPoint {
	if p.Infinity {
		return ECPointInfinity()
	}
	return ECPoint{X: p.X, Y: p.Y.Negate()}
}

// limbsBelowP reports whether x < p.
func limbsBelowP(x *[4]uint64) bool {
	_, b := bits.Sub64(x[0], p0, 0)
	_, b = bits.Sub64(x[1], p1, b)
	_, b = bits.Sub64(x[2], p2, b)
	_, b = bits.Sub64(x[3], p3, b)
	return b == 1
}

// IsOnCurve reports whether p is a finite point satisfying y^2 = x^3 + ax + b, with
// a = -3. The point at infinity gives false: it is never a valid key or ciphertext point.
func (p ECPoint) IsOnCurve() bool {
	if p.Infinity {
		return false
	}
	var x, y, lhs, rhs, t fe
	feToMont(&x, &p.X.value.limbs)
	feToMont(&y, &p.Y.value.limbs)
	feSqr(&lhs, &y)

	// rhs = x*(x^2 - 3) + b
	feSqr(&rhs, &x)
	feDouble(&t, &feOne)
	feAdd(&t, &t, &feOne)
	feSub(&rhs, &rhs, &t)
	feMul(&rhs, &rhs, &x)
	feAdd(&rhs, &rhs, &feB)
	return lhs == rhs
}

// Equal reports whether p and q are the same point.
func (p ECPoint) Equal(q ECPoint) bool {
	if p.Infinity && q.Infinity {
		return true
	}
	if p.Infinity || q.Infinity {
		return false
	}
	return p.X.Equal(q.X) && p.Y.Equal(q.Y)
}

// Add returns p + q.
func (p ECPoint) Add(q ECPoint) ECPoint {
	if p.Infinity {
		return q
	}
	if q.Infinity {
		return p
	}
	jp, jq := jacFromAffinePoint(&p), jacFromAffinePoint(&q)
	var sum jacPoint
	jacAddVar(&sum, &jp, &jq)
	return sum.toAffinePoint()
}

// Twice returns 2*p.
func (p ECPoint) Twice() ECPoint {
	if p.Infinity || p.Y.IsZero() {
		return ECPointInfinity()
	}
	jp := jacFromAffinePoint(&p)
	jacDouble(&jp, &jp)
	return jp.toAffinePoint()
}

// Subtract returns p - q.
func (p ECPoint) Subtract(q ECPoint) ECPoint {
	return p.Add(q.Negate())
}

// isGenerator compares public coordinates; it is not secret dependent.
func (p *ECPoint) isGenerator() bool {
	return !p.Infinity && p.X.value.limbs == curveGX && p.Y.value.limbs == curveGY
}

// Multiply returns [k]p with k reduced modulo the group order n. The running time does
// not depend on k. It returns the point at infinity if p is off the curve, so an invalid
// point cannot be used to learn a secret k, and if k is nil.
func (p ECPoint) Multiply(k *BigInt256) ECPoint {
	if k == nil || !p.IsOnCurve() {
		return ECPointInfinity()
	}
	r := multiplyJacobian(&p, k)
	return r.toAffinePoint()
}

// multiplyJacobian is Multiply without the final conversion to affine form.
func multiplyJacobian(p *ECPoint, k *BigInt256) jacPoint {
	var r jacPoint
	if p.Infinity {
		return r
	}
	scalar := scalarReduce(&k.limbs)
	if p.isGenerator() {
		jacScalarBaseMult(&r, &scalar)
	} else {
		jp := jacFromAffinePoint(p)
		jacScalarMult(&r, &jp, &scalar)
	}
	return r
}

// sm2BaseMult returns [k]G in Jacobian form, reducing k modulo n in constant time.
func sm2BaseMult(k *BigInt256) jacPoint {
	scalar := scalarReduce(&k.limbs)
	var r jacPoint
	jacScalarBaseMult(&r, &scalar)
	return r
}
