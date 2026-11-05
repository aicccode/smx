package smx

import (
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"strings"
)

// BigInt256 is a 256-bit unsigned integer stored as 4 uint64 limbs in little-endian order.
// limbs[0] is the least significant 64-bit word.
type BigInt256 struct {
	limbs [4]uint64
}

var bigOne = BigInt256{limbs: [4]uint64{1, 0, 0, 0}}

// BigInt256FromHex parses a big-endian hex string, with an optional 0x prefix, into a
// BigInt256. Parsing is lenient: only the last 32 bytes are kept, and decoding stops at
// the first invalid digit, using the bytes decoded so far.
func BigInt256FromHex(s string) BigInt256 {
	// The common case: exactly 64 valid digits.
	if len(s) == 64 {
		var buf [32]byte
		if decodeHexInto(buf[:], s) {
			return BigInt256FromBEBytes(buf[:])
		}
	}
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if len(s)%2 == 1 {
		s = "0" + s
	}
	b, _ := hex.DecodeString(s)
	return BigInt256FromBEBytes(b)
}

// BigInt256FromBEBytes creates a BigInt256 from a big-endian byte slice. Input shorter
// than 32 bytes is left padded with zeros; for longer input only the last 32 bytes count.
func BigInt256FromBEBytes(b []byte) BigInt256 {
	var padded [32]byte
	if len(b) > 32 {
		b = b[len(b)-32:]
	}
	copy(padded[32-len(b):], b)
	return BigInt256{limbs: [4]uint64{
		binary.BigEndian.Uint64(padded[24:]),
		binary.BigEndian.Uint64(padded[16:]),
		binary.BigEndian.Uint64(padded[8:]),
		binary.BigEndian.Uint64(padded[0:]),
	}}
}

// putLimbsBE writes four little-endian limbs as 32 big-endian bytes.
func putLimbsBE(out *[32]byte, limbs *[4]uint64) {
	binary.BigEndian.PutUint64(out[0:], limbs[3])
	binary.BigEndian.PutUint64(out[8:], limbs[2])
	binary.BigEndian.PutUint64(out[16:], limbs[1])
	binary.BigEndian.PutUint64(out[24:], limbs[0])
}

// ToBEBytes converts to a 32-byte big-endian representation.
func (a BigInt256) ToBEBytes() [32]byte {
	var out [32]byte
	putLimbsBE(&out, &a.limbs)
	return out
}

// ToHex returns the uppercase hex string (64 chars, zero-padded).
func (a BigInt256) ToHex() string {
	return a.hexString(0x07)
}

// ToHexLower returns the lowercase hex string (64 chars, zero-padded).
func (a BigInt256) ToHexLower() string {
	return a.hexString(0x27)
}

func (a *BigInt256) hexString(alphaOffset uint64) string {
	var raw [32]byte
	putLimbsBE(&raw, &a.limbs)
	out := make([]byte, 64)
	encodeHexTo(out, raw[:], alphaOffset)
	return bytesAsString(out)
}

// IsZero returns true if the value is zero.
func (a BigInt256) IsZero() bool {
	return a.limbs[0]|a.limbs[1]|a.limbs[2]|a.limbs[3] == 0
}

// IsOne returns true if the value is one.
func (a BigInt256) IsOne() bool {
	return a.limbs[0] == 1 && a.limbs[1]|a.limbs[2]|a.limbs[3] == 0
}

// Compare returns -1, 0, or 1. It stops at the first differing limb, so it is not
// constant time.
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
	var c uint64
	r.limbs[0], c = bits.Add64(a.limbs[0], b.limbs[0], 0)
	r.limbs[1], c = bits.Add64(a.limbs[1], b.limbs[1], c)
	r.limbs[2], c = bits.Add64(a.limbs[2], b.limbs[2], c)
	r.limbs[3], c = bits.Add64(a.limbs[3], b.limbs[3], c)
	return r, c
}

// Sub returns (a - b, borrow).
func (a BigInt256) Sub(b *BigInt256) (BigInt256, uint64) {
	var r BigInt256
	var c uint64
	r.limbs[0], c = bits.Sub64(a.limbs[0], b.limbs[0], 0)
	r.limbs[1], c = bits.Sub64(a.limbs[1], b.limbs[1], c)
	r.limbs[2], c = bits.Sub64(a.limbs[2], b.limbs[2], c)
	r.limbs[3], c = bits.Sub64(a.limbs[3], b.limbs[3], c)
	return r, c
}

// Mul returns the full 512-bit product as [8]uint64 (little-endian).
func (a BigInt256) Mul(b *BigInt256) [8]uint64 {
	t0, t1, t2, t3, t4, t5, t6, t7 := mul512(&a.limbs, &b.limbs)
	return [8]uint64{t0, t1, t2, t3, t4, t5, t6, t7}
}

// ModAdd returns (a + b) mod m for inputs below m. It subtracts m at most once, without
// branching on the values.
func (a BigInt256) ModAdd(b, m *BigInt256) BigInt256 {
	sum, carry := a.Add(b)
	reduced, borrow := sum.Sub(m)
	useSum := -(borrow &^ carry)
	return BigInt256{limbs: [4]uint64{
		(sum.limbs[0] & useSum) | (reduced.limbs[0] &^ useSum),
		(sum.limbs[1] & useSum) | (reduced.limbs[1] &^ useSum),
		(sum.limbs[2] & useSum) | (reduced.limbs[2] &^ useSum),
		(sum.limbs[3] & useSum) | (reduced.limbs[3] &^ useSum),
	}}
}

// ModSub returns (a - b) mod m for inputs below m, without branching on the values.
func (a BigInt256) ModSub(b, m *BigInt256) BigInt256 {
	diff, borrow := a.Sub(b)
	mask := -borrow
	addend := BigInt256{limbs: [4]uint64{
		m.limbs[0] & mask, m.limbs[1] & mask, m.limbs[2] & mask, m.limbs[3] & mask,
	}}
	r, _ := diff.Add(&addend)
	return r
}

// ModMul returns (a * b) mod m. Multiplication modulo SM2_P or SM2_N is constant time;
// for any other modulus it uses variable-time long division.
func (a BigInt256) ModMul(b, m *BigInt256) BigInt256 {
	var r BigInt256
	switch m.limbs {
	case [4]uint64{p0, p1, p2, p3}:
		r = a.SM2ModMulP(b)
	case [4]uint64{n0, n1, n2, n3}:
		scalarMul(&r.limbs, &a.limbs, &b.limbs)
	default:
		product := a.Mul(b)
		r = modReduce512(&product, m)
	}
	return r
}

// ModSquare returns (a * a) mod m.
func (a BigInt256) ModSquare(m *BigInt256) BigInt256 {
	return a.ModMul(&a, m)
}

// SM2ModMulP returns (a * b) mod SM2_P.
func (a BigInt256) SM2ModMulP(b *BigInt256) BigInt256 {
	x := feReduce(&a.limbs)
	var t, r fe
	feMul(&t, &x, (*fe)(&b.limbs))
	feMul(&r, &t, &feRR)
	return BigInt256{limbs: r}
}

// SM2ModSquareP returns (a * a) mod SM2_P.
func (a BigInt256) SM2ModSquareP() BigInt256 {
	x := feReduce(&a.limbs)
	var t, r fe
	feSqr(&t, &x)
	feMul(&r, &t, &feRR)
	return BigInt256{limbs: r}
}

// modReduce512 returns value mod modulus using Knuth's algorithm D with 64-bit digits.
// It panics if modulus is zero. Its timing depends on the operands, so secret
// values must take the Montgomery paths instead.
func modReduce512(value *[8]uint64, modulus *BigInt256) BigInt256 {
	n := 4
	for n > 0 && modulus.limbs[n-1] == 0 {
		n--
	}
	if n == 0 {
		panic("division by zero")
	}

	if n == 1 {
		d := modulus.limbs[0]
		var rem uint64
		for i := 7; i >= 0; i-- {
			_, rem = bits.Div64(rem, value[i], d)
		}
		return BigInt256{limbs: [4]uint64{rem, 0, 0, 0}}
	}

	// Normalize so the divisor's top bit is set.
	shift := uint(bits.LeadingZeros64(modulus.limbs[n-1]))
	var d [4]uint64
	for i := n - 1; i > 0; i-- {
		d[i] = modulus.limbs[i]<<shift | modulus.limbs[i-1]>>(64-shift)
	}
	d[0] = modulus.limbs[0] << shift

	var u [9]uint64
	u[8] = value[7] >> (64 - shift)
	for i := 7; i > 0; i-- {
		u[i] = value[i]<<shift | value[i-1]>>(64-shift)
	}
	u[0] = value[0] << shift

	top, next := d[n-1], d[n-2]
	for j := 8 - n; j >= 0; j-- {
		// Estimate the quotient digit from the top limbs and correct it.
		var qhat, rhat uint64
		overflow := false
		if u[j+n] >= top {
			qhat = ^uint64(0)
			var c uint64
			rhat, c = bits.Add64(u[j+n-1], top, 0)
			overflow = c != 0
		} else {
			qhat, rhat = bits.Div64(u[j+n], u[j+n-1], top)
		}
		for !overflow {
			hi, lo := bits.Mul64(qhat, next)
			if hi < rhat || (hi == rhat && lo <= u[j+n-2]) {
				break
			}
			qhat--
			var c uint64
			rhat, c = bits.Add64(rhat, top, 0)
			overflow = c != 0
		}

		// Multiply and subtract.
		var mulCarry, borrow uint64
		for i := 0; i < n; i++ {
			hi, lo := bits.Mul64(qhat, d[i])
			var c uint64
			lo, c = bits.Add64(lo, mulCarry, 0)
			mulCarry = hi + c
			u[i+j], borrow = bits.Sub64(u[i+j], lo, borrow)
		}
		u[j+n], borrow = bits.Sub64(u[j+n], mulCarry, borrow)

		// The estimate was one too large in rare cases: add the divisor back.
		if borrow != 0 {
			var c uint64
			for i := 0; i < n; i++ {
				u[i+j], c = bits.Add64(u[i+j], d[i], c)
			}
			u[j+n] += c
		}
	}

	// Denormalize the remainder.
	var r BigInt256
	for i := 0; i < n; i++ {
		r.limbs[i] = u[i]>>shift | u[i+1]<<(64-shift)
	}
	return r
}

// ModInverse returns a^(-1) mod m using Fermat's little theorem, so m must be prime.
func (a BigInt256) ModInverse(m *BigInt256) BigInt256 {
	two := BigInt256{limbs: [4]uint64{2, 0, 0, 0}}
	exp, _ := m.Sub(&two)
	return a.ModPow(&exp, m)
}

// ModPow returns (a^exp) mod m using a 4-bit window. The timing depends on exp.
func (a BigInt256) ModPow(exp, m *BigInt256) BigInt256 {
	bitLen := exp.BitLength()
	if bitLen == 0 {
		return bigOne
	}

	var table [16]BigInt256
	table[1] = a.ModMul(&bigOne, m)
	for i := 2; i < 16; i++ {
		table[i] = table[i-1].ModMul(&table[1], m)
	}

	// Align the windows to multiples of 4 bits from the bottom.
	top := (bitLen - 1) / 4 * 4
	result := table[(exp.limbs[top/64]>>uint(top%64))&0xF]
	for pos := top - 4; pos >= 0; pos -= 4 {
		for i := 0; i < 4; i++ {
			result = result.ModMul(&result, m)
		}
		window := (exp.limbs[pos/64] >> uint(pos%64)) & 0xF
		if window != 0 {
			result = result.ModMul(&table[window], m)
		}
	}
	return result
}

// GetBit returns the bit at position i (0 = LSB).
func (a BigInt256) GetBit(i int) bool {
	if i >= 256 {
		return false
	}
	return (a.limbs[i/64]>>uint(i%64))&1 == 1
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
	return BigInt256{limbs: [4]uint64{
		a.limbs[0] & b.limbs[0],
		a.limbs[1] & b.limbs[1],
		a.limbs[2] & b.limbs[2],
		a.limbs[3] & b.limbs[3],
	}}
}

// ShiftRight1 returns a >> 1.
func (a BigInt256) ShiftRight1() BigInt256 {
	return BigInt256{limbs: [4]uint64{
		a.limbs[0]>>1 | a.limbs[1]<<63,
		a.limbs[1]>>1 | a.limbs[2]<<63,
		a.limbs[2]>>1 | a.limbs[3]<<63,
		a.limbs[3] >> 1,
	}}
}

// ShiftLeft1 returns a << 1.
func (a BigInt256) ShiftLeft1() BigInt256 {
	return BigInt256{limbs: [4]uint64{
		a.limbs[0] << 1,
		a.limbs[1]<<1 | a.limbs[0]>>63,
		a.limbs[2]<<1 | a.limbs[1]>>63,
		a.limbs[3]<<1 | a.limbs[2]>>63,
	}}
}
