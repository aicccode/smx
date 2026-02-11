package smx

import "encoding/hex"

// SM2 curve constants
var (
	SM2_A = FpElement{value: BigInt256{limbs: [4]uint64{
		0xFFFFFFFFFFFFFFFC, 0xFFFFFFFF00000000,
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF,
	}}}

	SM2_B = FpElement{value: BigInt256{limbs: [4]uint64{
		0xDDBCBD414D940E93, 0xF39789F515AB8F92,
		0x4D5A9E4BCF6509A7, 0x28E9FA9E9D9F5E34,
	}}}

	SM2_GX = FpElement{value: BigInt256{limbs: [4]uint64{
		0x715A4589334C74C7, 0x8FE30BBFF2660BE1,
		0x5F9904466A39C994, 0x32C4AE2C1F198119,
	}}}

	SM2_GY = FpElement{value: BigInt256{limbs: [4]uint64{
		0x02DF32E52139F0A0, 0xD0A9877CC62A4740,
		0x59BDCEE36B692153, 0xBC3736A2F4F6779C,
	}}}

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

func NewECPoint(x, y FpElement) ECPoint {
	return ECPoint{X: x, Y: y, Infinity: false}
}

func ECPointInfinity() ECPoint {
	return ECPoint{X: FpZero(), Y: FpZero(), Infinity: true}
}

func ECPointGenerator() ECPoint {
	return NewECPoint(SM2_GX, SM2_GY)
}

func ECPointFromHex(xHex, yHex string) ECPoint {
	return NewECPoint(FpFromHex(xHex), FpFromHex(yHex))
}

// ECPointFromEncoded decodes from 04||x||y format.
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

// ECPointFromHexEncoded decodes from a hex string of 04||x||y.
func ECPointFromHexEncoded(s string) ECPoint {
	b, _ := hex.DecodeString(s)
	return ECPointFromEncoded(b)
}

// ToEncoded encodes the point as 04||x||y bytes.
func (p ECPoint) ToEncoded() []byte {
	if p.Infinity {
		return []byte{0x00}
	}
	result := make([]byte, 65)
	result[0] = 0x04
	xb := p.X.ToBEBytes()
	yb := p.Y.ToBEBytes()
	copy(result[1:33], xb[:])
	copy(result[33:65], yb[:])
	return result
}

// ToHexEncoded encodes the point as a lowercase hex string.
func (p ECPoint) ToHexEncoded() string {
	return hex.EncodeToString(p.ToEncoded())
}

func (p ECPoint) Negate() ECPoint {
	if p.Infinity {
		return ECPointInfinity()
	}
	return ECPoint{X: p.X, Y: p.Y.Negate(), Infinity: false}
}

func (p ECPoint) IsOnCurve() bool {
	if p.Infinity {
		return true
	}
	// y^2 = x^3 + a*x + b
	lhs := p.Y.Square()
	rhs := p.X.Square().Add(SM2_A).Mul(p.X).Add(SM2_B)
	return lhs.Equal(rhs)
}

func (p ECPoint) Equal(q ECPoint) bool {
	if p.Infinity && q.Infinity {
		return true
	}
	if p.Infinity || q.Infinity {
		return false
	}
	return p.X.Equal(q.X) && p.Y.Equal(q.Y)
}

// Add returns p + q (affine + affine via Jacobian mixed addition).
func (p ECPoint) Add(q ECPoint) ECPoint {
	if p.Infinity {
		return q
	}
	if q.Infinity {
		return p
	}
	jp := jacobianFromAffine(p)
	result := jp.addAffine(q)
	return result.toAffine()
}

// Twice returns 2*p.
func (p ECPoint) Twice() ECPoint {
	if p.Infinity || p.Y.IsZero() {
		return ECPointInfinity()
	}
	jp := jacobianFromAffine(p)
	return jp.double().toAffine()
}

// Subtract returns p - q.
func (p ECPoint) Subtract(q ECPoint) ECPoint {
	neg := q.Negate()
	return p.Add(neg)
}

// Multiply returns [k]P using double-and-add with Jacobian coordinates.
func (p ECPoint) Multiply(k *BigInt256) ECPoint {
	if k.IsZero() || p.Infinity {
		return ECPointInfinity()
	}
	if k.IsOne() {
		return p
	}

	result := jacobianInfinity()
	bitLen := k.BitLength()
	for i := bitLen - 1; i >= 0; i-- {
		result = result.double()
		if k.GetBit(i) {
			result = result.addAffine(p)
		}
	}
	return result.toAffine()
}

// jacobianPoint is an internal Jacobian-coordinate representation.
type jacobianPoint struct {
	x, y, z FpElement
}

func jacobianInfinity() jacobianPoint {
	return jacobianPoint{x: FpOne(), y: FpOne(), z: FpZero()}
}

func jacobianFromAffine(p ECPoint) jacobianPoint {
	if p.Infinity {
		return jacobianInfinity()
	}
	return jacobianPoint{x: p.X, y: p.Y, z: FpOne()}
}

func (j jacobianPoint) toAffine() ECPoint {
	if j.z.IsZero() {
		return ECPointInfinity()
	}
	zInv := j.z.Invert()
	zInv2 := zInv.Square()
	zInv3 := zInv2.Mul(zInv)
	x := j.x.Mul(zInv2)
	y := j.y.Mul(zInv3)
	return NewECPoint(x, y)
}

// double uses the a=-3 optimization (dbl-2001-b).
func (j jacobianPoint) double() jacobianPoint {
	if j.z.IsZero() || j.y.IsZero() {
		return jacobianInfinity()
	}

	delta := j.z.Square()
	gamma := j.y.Square()
	beta := j.x.Mul(gamma)

	// alpha = 3*(X1-delta)*(X1+delta) (using a=-3)
	alpha := j.x.Sub(delta).Mul(j.x.Add(delta)).Triple()

	// X3 = alpha^2 - 8*beta
	beta8 := beta.Double().Double().Double()
	x3 := alpha.Square().Sub(beta8)

	// Z3 = (Y1+Z1)^2 - gamma - delta
	z3 := j.y.Add(j.z).Square().Sub(gamma).Sub(delta)

	// Y3 = alpha*(4*beta - X3) - 8*gamma^2
	beta4 := beta.Double().Double()
	gammaSq8 := gamma.Square().Double().Double().Double()
	y3 := alpha.Mul(beta4.Sub(x3)).Sub(gammaSq8)

	return jacobianPoint{x: x3, y: y3, z: z3}
}

// addAffine performs mixed addition (Jacobian + affine).
func (j jacobianPoint) addAffine(q ECPoint) jacobianPoint {
	if q.Infinity {
		return j
	}
	if j.z.IsZero() {
		return jacobianFromAffine(q)
	}

	z1z1 := j.z.Square()
	u2 := q.X.Mul(z1z1)
	s2 := q.Y.Mul(j.z).Mul(z1z1)
	h := u2.Sub(j.x)
	r := s2.Sub(j.y)

	if h.IsZero() {
		if r.IsZero() {
			return j.double()
		}
		return jacobianInfinity()
	}

	hh := h.Square()
	hhh := hh.Mul(h)
	x1hh := j.x.Mul(hh)
	x3 := r.Square().Sub(hhh).Sub(x1hh.Double())
	y3 := r.Mul(x1hh.Sub(x3)).Sub(j.y.Mul(hhh))
	z3 := j.z.Mul(h)

	return jacobianPoint{x: x3, y: y3, z: z3}
}
