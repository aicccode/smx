package smx

import "encoding/hex"

// SM2 curve constants.
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

// NewECPoint returns the finite point (x, y). It does not check that the point is on
// the curve.
func NewECPoint(x, y FpElement) ECPoint {
	return ECPoint{X: x, Y: y}
}

// ECPointInfinity returns the point at infinity.
func ECPointInfinity() ECPoint {
	return ECPoint{Infinity: true}
}

// ECPointGenerator returns the curve generator G.
func ECPointGenerator() ECPoint {
	return NewECPoint(SM2_GX, SM2_GY)
}

// ECPointFromHex returns the point with the given hex coordinates.
func ECPointFromHex(xHex, yHex string) ECPoint {
	return NewECPoint(FpFromHex(xHex), FpFromHex(yHex))
}

// ECPointFromEncoded decodes from 04||x||y format. Empty input decodes to the point
// at infinity; any other malformed input panics.
func ECPointFromEncoded(data []byte) ECPoint {
	if len(data) == 0 {
		return ECPointInfinity()
	}
	if data[0] != 0x04 || len(data) != 65 {
		panic("invalid point encoding")
	}
	x := NewFpElement(BigInt256FromBEBytes(data[1:33]))
	y := NewFpElement(BigInt256FromBEBytes(data[33:65]))
	return NewECPoint(x, y)
}

// ECPointFromHexEncoded decodes from a hex string of 04||x||y. Decoding stops at the
// first invalid hex digit and keeps what came before it.
func ECPointFromHexEncoded(s string) ECPoint {
	if len(s) == 130 {
		var buf [65]byte
		if decodeHexInto(buf[:], s) {
			return ECPointFromEncoded(buf[:])
		}
	}
	b, _ := hex.DecodeString(s)
	return ECPointFromEncoded(b)
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

// IsOnCurve reports whether p satisfies y^2 = x^3 + ax + b, with a = -3. The point
// at infinity counts as on the curve.
func (p ECPoint) IsOnCurve() bool {
	if p.Infinity {
		return true
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
	return !p.Infinity && p.X.value == SM2_GX.value && p.Y.value == SM2_GY.value
}

// Multiply returns [k]p with k reduced modulo the group order n. The running time
// does not depend on k. It relies on p being a point of the curve; the result for an
// off-curve point is unspecified.
func (p ECPoint) Multiply(k *BigInt256) ECPoint {
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
