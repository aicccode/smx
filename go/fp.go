package smx

// SM2_P is the prime for the SM2 curve: p = 2^256 - 2^224 - 2^96 + 2^64 - 1
var SM2_P = BigInt256{
	limbs: [4]uint64{
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFF00000000,
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFEFFFFFFFF,
	},
}

// FpElement represents a field element modulo SM2_P.
type FpElement struct {
	value BigInt256
}

func NewFpElement(v BigInt256) FpElement {
	if v.Compare(&SM2_P) >= 0 {
		v = v.ModSub(&SM2_P, &SM2_P)
	}
	return FpElement{value: v}
}

func FpFromHex(s string) FpElement {
	return NewFpElement(BigInt256FromHex(s))
}

func FpZero() FpElement {
	return FpElement{value: bigZero}
}

func FpOne() FpElement {
	return FpElement{value: bigOne}
}

func (a FpElement) IsZero() bool {
	return a.value.IsZero()
}

func (a FpElement) IsOne() bool {
	return a.value.IsOne()
}

func (a FpElement) Add(b FpElement) FpElement {
	return FpElement{value: a.value.ModAdd(&b.value, &SM2_P)}
}

func (a FpElement) Sub(b FpElement) FpElement {
	return FpElement{value: a.value.ModSub(&b.value, &SM2_P)}
}

func (a FpElement) Mul(b FpElement) FpElement {
	return FpElement{value: a.value.SM2ModMulP(&b.value)}
}

func (a FpElement) Square() FpElement {
	return FpElement{value: a.value.SM2ModSquareP()}
}

func (a FpElement) Negate() FpElement {
	if a.IsZero() {
		return a
	}
	return FpElement{value: SM2_P.ModSub(&a.value, &SM2_P)}
}

// Invert returns a^(-1) mod p using Fermat's little theorem with SM2 fast reduction.
func (a FpElement) Invert() FpElement {
	if a.IsZero() {
		panic("cannot invert zero")
	}
	two := BigInt256{limbs: [4]uint64{2, 0, 0, 0}}
	pMinus2, _ := SM2_P.Sub(&two)
	result := bigOne
	base := a.value
	bitLen := pMinus2.BitLength()
	for i := 0; i < bitLen; i++ {
		if pMinus2.GetBit(i) {
			result = result.SM2ModMulP(&base)
		}
		base = base.SM2ModSquareP()
	}
	return FpElement{value: result}
}

func (a FpElement) Div(b FpElement) FpElement {
	inv := b.Invert()
	return a.Mul(inv)
}

func (a FpElement) Double() FpElement {
	return a.Add(a)
}

func (a FpElement) Triple() FpElement {
	return a.Double().Add(a)
}

func (a FpElement) ToBigInt() BigInt256 {
	return a.value
}

func (a FpElement) ToBEBytes() [32]byte {
	return a.value.ToBEBytes()
}

func (a FpElement) ToHex() string {
	return a.value.ToHex()
}

func (a FpElement) Equal(b FpElement) bool {
	return a.value == b.value
}
