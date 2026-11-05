package smx

// SM2_P is the prime for the SM2 curve: p = 2^256 - 2^224 - 2^96 + 2^64 - 1.
//
// The exported curve variables are for reading only. The library itself never reads
// them, so changing one cannot alter its behavior.
var SM2_P = BigInt256{limbs: [4]uint64{p0, p1, p2, p3}}

// curveP is the private copy of the prime used internally.
var curveP = [4]uint64{p0, p1, p2, p3}

// FpElement represents a field element modulo SM2_P. The value is held in plain form,
// fully reduced; curve operations convert to the faster internal Montgomery form.
type FpElement struct {
	value BigInt256
}

// NewFpElement reduces v modulo p. Any 256-bit value is below 2p. Point decoders do not
// use it: they reject coordinates at or above p rather than reduce them.
func NewFpElement(v BigInt256) FpElement {
	return FpElement{value: BigInt256{limbs: feReduce(&v.limbs)}}
}

// FpFromHex parses a big-endian hex string and reduces it modulo p. It returns zero for
// input BigInt256FromHex does not accept.
func FpFromHex(s string) FpElement {
	return NewFpElement(BigInt256FromHex(s))
}

// FpZero returns 0.
func FpZero() FpElement {
	return FpElement{}
}

// FpOne returns 1.
func FpOne() FpElement {
	return FpElement{value: bigOne}
}

// IsZero reports whether a is 0.
func (a FpElement) IsZero() bool {
	return a.value.IsZero()
}

// IsOne reports whether a is 1.
func (a FpElement) IsOne() bool {
	return a.value.IsOne()
}

// Add returns a + b mod p.
func (a FpElement) Add(b FpElement) FpElement {
	var z fe
	feAdd(&z, (*fe)(&a.value.limbs), (*fe)(&b.value.limbs))
	return FpElement{value: BigInt256{limbs: z}}
}

// Sub returns a - b mod p.
func (a FpElement) Sub(b FpElement) FpElement {
	var z fe
	feSub(&z, (*fe)(&a.value.limbs), (*fe)(&b.value.limbs))
	return FpElement{value: BigInt256{limbs: z}}
}

// Mul returns a * b mod p.
func (a FpElement) Mul(b FpElement) FpElement {
	return FpElement{value: a.value.SM2ModMulP(&b.value)}
}

// Square returns a * a mod p.
func (a FpElement) Square() FpElement {
	return FpElement{value: a.value.SM2ModSquareP()}
}

// Negate returns -a mod p.
func (a FpElement) Negate() FpElement {
	var z fe
	feNeg(&z, (*fe)(&a.value.limbs))
	return FpElement{value: BigInt256{limbs: z}}
}

// Invert returns a^-1 mod p, or 0 if a is 0.
func (a FpElement) Invert() FpElement {
	var m, inv fe
	feToMont(&m, &a.value.limbs)
	feInvert(&inv, &m)
	return FpElement{value: BigInt256{limbs: feFromMont(&inv)}}
}

// Div returns a / b mod p, or 0 if b is 0.
func (a FpElement) Div(b FpElement) FpElement {
	return a.Mul(b.Invert())
}

// Double returns 2 * a mod p.
func (a FpElement) Double() FpElement {
	return a.Add(a)
}

// Triple returns 3 * a mod p.
func (a FpElement) Triple() FpElement {
	return a.Double().Add(a)
}

// ToBigInt returns the plain value.
func (a FpElement) ToBigInt() BigInt256 {
	return a.value
}

// ToBEBytes returns the 32-byte big-endian encoding.
func (a FpElement) ToBEBytes() [32]byte {
	return a.value.ToBEBytes()
}

// ToHex returns the 64-digit uppercase hex encoding.
func (a FpElement) ToHex() string {
	return a.value.ToHex()
}

// Equal reports whether a and b are equal.
func (a FpElement) Equal(b FpElement) bool {
	return limbsEqual(&a.value.limbs, &b.value.limbs)
}
