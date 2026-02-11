package smx

import (
	"encoding/hex"
	"math/bits"
	"strings"
)

// BigInt256 is a 256-bit unsigned integer stored as 4 uint64 limbs in little-endian order.
// limbs[0] is the least significant 64-bit word.
type BigInt256 struct {
	limbs [4]uint64
}

var (
	bigZero = BigInt256{}
	bigOne  = BigInt256{limbs: [4]uint64{1, 0, 0, 0}}
)

// BigInt256FromHex parses a big-endian hex string into a BigInt256.
func BigInt256FromHex(s string) BigInt256 {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if len(s)%2 == 1 {
		s = "0" + s
	}
	b, _ := hex.DecodeString(s)
	padded := make([]byte, 32)
	start := 32 - len(b)
	if start < 0 {
		start = 0
		b = b[len(b)-32:]
	}
	copy(padded[start:], b)
	return BigInt256FromBEBytes(padded)
}

// BigInt256FromBEBytes creates a BigInt256 from a big-endian byte slice (up to 32 bytes).
func BigInt256FromBEBytes(b []byte) BigInt256 {
	var padded [32]byte
	start := 32 - len(b)
	if start < 0 {
		start = 0
		b = b[len(b)-32:]
	}
	copy(padded[start:], b)

	var r BigInt256
	for i := 0; i < 4; i++ {
		off := (3 - i) * 8
		r.limbs[i] = uint64(padded[off])<<56 | uint64(padded[off+1])<<48 |
			uint64(padded[off+2])<<40 | uint64(padded[off+3])<<32 |
			uint64(padded[off+4])<<24 | uint64(padded[off+5])<<16 |
			uint64(padded[off+6])<<8 | uint64(padded[off+7])
	}
	return r
}

// ToBEBytes converts to a 32-byte big-endian representation.
func (a BigInt256) ToBEBytes() [32]byte {
	var out [32]byte
	for i := 0; i < 4; i++ {
		off := (3 - i) * 8
		out[off] = byte(a.limbs[i] >> 56)
		out[off+1] = byte(a.limbs[i] >> 48)
		out[off+2] = byte(a.limbs[i] >> 40)
		out[off+3] = byte(a.limbs[i] >> 32)
		out[off+4] = byte(a.limbs[i] >> 24)
		out[off+5] = byte(a.limbs[i] >> 16)
		out[off+6] = byte(a.limbs[i] >> 8)
		out[off+7] = byte(a.limbs[i])
	}
	return out
}

// ToHex returns the uppercase hex string (64 chars, zero-padded).
func (a BigInt256) ToHex() string {
	b := a.ToBEBytes()
	return strings.ToUpper(hex.EncodeToString(b[:]))
}

// ToHexLower returns the lowercase hex string (64 chars, zero-padded).
func (a BigInt256) ToHexLower() string {
	b := a.ToBEBytes()
	return hex.EncodeToString(b[:])
}

// IsZero returns true if the value is zero.
func (a BigInt256) IsZero() bool {
	return a.limbs[0] == 0 && a.limbs[1] == 0 && a.limbs[2] == 0 && a.limbs[3] == 0
}

// IsOne returns true if the value is one.
func (a BigInt256) IsOne() bool {
	return a.limbs[0] == 1 && a.limbs[1] == 0 && a.limbs[2] == 0 && a.limbs[3] == 0
}

// Compare returns -1, 0, or 1.
func (a BigInt256) Compare(b *BigInt256) int {
	for i := 3; i >= 0; i-- {
		if a.limbs[i] > b.limbs[i] {
			return 1
		}
		if a.limbs[i] < b.limbs[i] {
			return -1
		}
	}
	return 0
}

// Add returns (a + b, carry).
func (a BigInt256) Add(b *BigInt256) (BigInt256, uint64) {
	var r BigInt256
	var carry uint64
	for i := 0; i < 4; i++ {
		sum, c1 := bits.Add64(a.limbs[i], b.limbs[i], carry)
		r.limbs[i] = sum
		carry = c1
	}
	return r, carry
}

// Sub returns (a - b, borrow).
func (a BigInt256) Sub(b *BigInt256) (BigInt256, uint64) {
	var r BigInt256
	var borrow uint64
	for i := 0; i < 4; i++ {
		diff, b1 := bits.Sub64(a.limbs[i], b.limbs[i], borrow)
		r.limbs[i] = diff
		borrow = b1
	}
	return r, borrow
}

// Mul returns the full 512-bit product as [8]uint64 (little-endian).
func (a BigInt256) Mul(b *BigInt256) [8]uint64 {
	var result [8]uint64
	for i := 0; i < 4; i++ {
		var carry uint64
		for j := 0; j < 4; j++ {
			hi, lo := bits.Mul64(a.limbs[i], b.limbs[j])
			lo, c1 := bits.Add64(lo, result[i+j], 0)
			hi += c1
			lo2, c2 := bits.Add64(lo, carry, 0)
			hi += c2
			result[i+j] = lo2
			carry = hi
		}
		result[i+4] = carry
	}
	return result
}

// ModAdd returns (a + b) mod m.
func (a BigInt256) ModAdd(b, m *BigInt256) BigInt256 {
	sum, carry := a.Add(b)
	if carry != 0 || sum.Compare(m) >= 0 {
		r, _ := sum.Sub(m)
		return r
	}
	return sum
}

// ModSub returns (a - b) mod m.
func (a BigInt256) ModSub(b, m *BigInt256) BigInt256 {
	diff, borrow := a.Sub(b)
	if borrow != 0 {
		r, _ := diff.Add(m)
		return r
	}
	return diff
}

// ModMul returns (a * b) mod m using generic 512-bit reduction.
func (a BigInt256) ModMul(b, m *BigInt256) BigInt256 {
	product := a.Mul(b)
	return modReduce512(&product, m)
}

// ModSquare returns (a * a) mod m.
func (a BigInt256) ModSquare(m *BigInt256) BigInt256 {
	return a.ModMul(&a, m)
}

// SM2ModMulP returns (a * b) mod SM2_P using fast Solinas reduction.
func (a BigInt256) SM2ModMulP(b *BigInt256) BigInt256 {
	product := a.Mul(b)
	return sm2ModReduceP(&product)
}

// SM2ModSquareP returns (a * a) mod SM2_P using fast Solinas reduction.
func (a BigInt256) SM2ModSquareP() BigInt256 {
	product := a.Mul(&a)
	return sm2ModReduceP(&product)
}

// sm2ModReduceP performs fast modular reduction for SM2 prime p.
// p = 2^256 - 2^224 - 2^96 + 2^64 - 1
func sm2ModReduceP(c *[8]uint64) BigInt256 {
	// Extract 32-bit words (little-endian)
	w := func(i int) int64 {
		if i%2 == 0 {
			return int64(c[i/2] & 0xFFFFFFFF)
		}
		return int64(c[i/2] >> 32)
	}

	// Pre-computed signed reduction coefficients
	var R = [8][8]int64{
		{1, 0, -1, 1, 0, 0, 0, 1},  // R_8
		{1, 1, -1, 0, 1, 0, 0, 1},  // R_9
		{1, 1, 0, 0, 0, 1, 0, 1},   // R_10
		{1, 1, 0, 1, 0, 0, 1, 1},   // R_11
		{1, 1, 0, 1, 1, 0, 0, 2},   // R_12
		{2, 1, -1, 2, 1, 1, 0, 2},  // R_13
		{2, 2, -1, 1, 2, 1, 1, 2},  // R_14
		{2, 2, 0, 1, 1, 2, 1, 3},   // R_15
	}

	var acc [9]int64
	for j := 0; j < 8; j++ {
		acc[j] = w(j)
		for i := 0; i < 8; i++ {
			acc[j] += w(i+8) * R[i][j]
		}
	}

	// Propagate carries (32-bit words)
	for i := 0; i < 8; i++ {
		carry := acc[i] >> 32
		acc[i] &= 0xFFFFFFFF
		acc[i+1] += carry
	}

	// Handle overflow
	overflow := acc[8]
	if overflow != 0 {
		acc[0] += overflow
		acc[2] -= overflow
		acc[3] += overflow
		acc[7] += overflow
		acc[8] = 0

		for i := 0; i < 8; i++ {
			carry := acc[i] >> 32
			acc[i] &= 0xFFFFFFFF
			acc[i+1] += carry
		}

		overflow2 := acc[8]
		if overflow2 != 0 {
			acc[0] += overflow2
			acc[2] -= overflow2
			acc[3] += overflow2
			acc[7] += overflow2
			acc[8] = 0
			for i := 0; i < 8; i++ {
				carry := acc[i] >> 32
				acc[i] &= 0xFFFFFFFF
				acc[i+1] += carry
			}
		}
	}

	// Handle negative values
	for i := 0; i < 8; i++ {
		for acc[i] < 0 {
			acc[i] += 0x100000000
			acc[i+1] -= 1
		}
	}

	result := BigInt256{
		limbs: [4]uint64{
			uint64(acc[0]) | (uint64(acc[1]) << 32),
			uint64(acc[2]) | (uint64(acc[3]) << 32),
			uint64(acc[4]) | (uint64(acc[5]) << 32),
			uint64(acc[6]) | (uint64(acc[7]) << 32),
		},
	}

	sm2P := BigInt256{
		limbs: [4]uint64{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF},
	}
	for result.Compare(&sm2P) >= 0 {
		result, _ = result.Sub(&sm2P)
	}
	return result
}

func modReduce512(value *[8]uint64, modulus *BigInt256) BigInt256 {
	var remainder [8]uint64
	copy(remainder[:], value[:])

	dividendBits := 0
	for i := 7; i >= 0; i-- {
		if remainder[i] != 0 {
			dividendBits = (i+1)*64 - bits.LeadingZeros64(remainder[i])
			break
		}
	}

	modulusBits := 0
	for i := 3; i >= 0; i-- {
		if modulus.limbs[i] != 0 {
			modulusBits = (i+1)*64 - bits.LeadingZeros64(modulus.limbs[i])
			break
		}
	}

	if modulusBits == 0 {
		panic("division by zero")
	}

	if dividendBits < modulusBits {
		return BigInt256{limbs: [4]uint64{remainder[0], remainder[1], remainder[2], remainder[3]}}
	}

	shiftAmount := dividendBits - modulusBits
	for shift := shiftAmount; shift >= 0; shift-- {
		shifted := shiftLeft512(&modulus.limbs, shift)
		if compare512(&remainder, &shifted) >= 0 {
			remainder = sub512(&remainder, &shifted)
		}
	}

	return BigInt256{limbs: [4]uint64{remainder[0], remainder[1], remainder[2], remainder[3]}}
}

func shiftLeft512(value *[4]uint64, shift int) [8]uint64 {
	var result [8]uint64
	if shift == 0 {
		copy(result[:4], value[:])
		return result
	}
	wordShift := shift / 64
	bitShift := uint(shift % 64)
	if bitShift == 0 {
		for i := 0; i < 4; i++ {
			if i+wordShift < 8 {
				result[i+wordShift] = value[i]
			}
		}
	} else {
		for i := 0; i < 4; i++ {
			if i+wordShift < 8 {
				result[i+wordShift] |= value[i] << bitShift
			}
			if i+wordShift+1 < 8 {
				result[i+wordShift+1] |= value[i] >> (64 - bitShift)
			}
		}
	}
	return result
}

func compare512(a, b *[8]uint64) int {
	for i := 7; i >= 0; i-- {
		if a[i] > b[i] {
			return 1
		}
		if a[i] < b[i] {
			return -1
		}
	}
	return 0
}

func sub512(a, b *[8]uint64) [8]uint64 {
	var result [8]uint64
	var borrow uint64
	for i := 0; i < 8; i++ {
		diff, b1 := bits.Sub64(a[i], b[i], borrow)
		result[i] = diff
		borrow = b1
	}
	return result
}

// ModInverse returns a^(-1) mod m using Fermat's little theorem.
func (a BigInt256) ModInverse(m *BigInt256) BigInt256 {
	two := BigInt256{limbs: [4]uint64{2, 0, 0, 0}}
	pMinus2, _ := m.Sub(&two)
	return a.ModPow(&pMinus2, m)
}

// ModPow returns (base^exp) mod m using square-and-multiply.
func (a BigInt256) ModPow(exp, m *BigInt256) BigInt256 {
	if exp.IsZero() {
		return bigOne
	}
	result := bigOne
	base := a
	bitLen := exp.BitLength()
	for i := 0; i < bitLen; i++ {
		if exp.GetBit(i) {
			result = result.ModMul(&base, m)
		}
		base = base.ModSquare(m)
	}
	return result
}

// GetBit returns the bit at position i (0 = LSB).
func (a BigInt256) GetBit(i int) bool {
	if i >= 256 {
		return false
	}
	word := i / 64
	bit := uint(i % 64)
	return (a.limbs[word]>>bit)&1 == 1
}

// BitLength returns the position of the highest set bit (0 for zero).
func (a BigInt256) BitLength() int {
	for i := 3; i >= 0; i-- {
		if a.limbs[i] != 0 {
			return (i+1)*64 - bits.LeadingZeros64(a.limbs[i])
		}
	}
	return 0
}

// And returns a & b.
func (a BigInt256) And(b *BigInt256) BigInt256 {
	return BigInt256{
		limbs: [4]uint64{
			a.limbs[0] & b.limbs[0],
			a.limbs[1] & b.limbs[1],
			a.limbs[2] & b.limbs[2],
			a.limbs[3] & b.limbs[3],
		},
	}
}

// ShiftRight1 returns a >> 1.
func (a BigInt256) ShiftRight1() BigInt256 {
	var r BigInt256
	for i := 0; i < 4; i++ {
		r.limbs[i] = a.limbs[i] >> 1
		if i < 3 {
			r.limbs[i] |= a.limbs[i+1] << 63
		}
	}
	return r
}

// ShiftLeft1 returns a << 1.
func (a BigInt256) ShiftLeft1() BigInt256 {
	var r BigInt256
	for i := 3; i >= 0; i-- {
		r.limbs[i] = a.limbs[i] << 1
		if i > 0 {
			r.limbs[i] |= a.limbs[i-1] >> 63
		}
	}
	return r
}
