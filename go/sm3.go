package smx

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
)

const sm3BlockSize = 64

var sm3IV = [8]uint32{
	0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
	0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
}

// sm3T holds the round constants T_j rotated left by j mod 32.
var sm3T = func() (t [64]uint32) {
	for j := range t {
		if j < 16 {
			t[j] = bits.RotateLeft32(0x79CC4519, j)
		} else {
			t[j] = bits.RotateLeft32(0x7A879D8A, j%32)
		}
	}
	return t
}()

// sm3MaxBytes is the longest message SM3 defines: its length field holds 2^64 - 1 bits.
const sm3MaxBytes = 1<<61 - 1

// SM3 implements the SM3 cryptographic hash function. An instance is reusable: Finish
// stores the digest and resets the state for the next message. The zero value is ready
// to use. An instance must not be shared between goroutines without synchronization.
type SM3 struct {
	v           [8]uint32
	buff        [sm3BlockSize]byte
	buffLen     int
	dataBitsLen uint64
	hashBytes   [32]byte
	ready       bool // v holds a valid chaining state
	finished    bool // hashBytes holds a digest
	tooLong     bool // the current message passed the 2^61 - 1 byte limit
}

// NewSM3 creates a new SM3 hash instance.
func NewSM3() *SM3 {
	return &SM3{v: sm3IV, ready: true}
}

// newSM3State returns an initialized instance by value, for use on the stack.
func newSM3State() SM3 {
	return SM3{v: sm3IV, ready: true}
}

// Format keeps hashed data, which can be secret, out of logs: every fmt verb prints a
// placeholder.
func (s SM3) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "SM3{redacted}")
}

// prepare makes the zero value usable and counts n more bytes of message.
func (s *SM3) prepare(n uint64) {
	if !s.ready {
		s.v = sm3IV
		s.ready = true
	}
	if n > sm3MaxBytes-s.dataBitsLen/8 {
		s.tooLong = true
		return
	}
	s.dataBitsLen += n * 8
}

// UpdateByte feeds a single byte into the hash.
func (s *SM3) UpdateByte(b byte) {
	if s == nil {
		return
	}
	s.prepare(1)
	s.buff[s.buffLen] = b
	s.buffLen++
	if s.buffLen == sm3BlockSize {
		sm3Blocks(&s.v, s.buff[:])
		s.buffLen = 0
	}
}

// Update feeds a byte slice into the hash.
func (s *SM3) Update(data []byte) {
	if s == nil {
		return
	}
	s.prepare(uint64(len(data)))
	if s.buffLen > 0 {
		n := copy(s.buff[s.buffLen:], data)
		s.buffLen += n
		if s.buffLen < sm3BlockSize {
			return
		}
		data = data[n:]
		sm3Blocks(&s.v, s.buff[:])
		s.buffLen = 0
	}
	if len(data) >= sm3BlockSize {
		whole := len(data) &^ (sm3BlockSize - 1)
		sm3Blocks(&s.v, data[:whole])
		data = data[whole:]
	}
	s.buffLen = copy(s.buff[:], data)
}

// Finish finalizes the hash computation and resets the instance for reuse. A message
// over 2^61 - 1 bytes has no digest: afterwards HashBytes returns zeros and
// HashHexUpper returns an empty string, rather than a digest of a wrapped length.
func (s *SM3) Finish() {
	if s == nil {
		return
	}
	s.prepare(0)
	failed := s.tooLong
	s.sum(&s.hashBytes)
	if failed {
		s.hashBytes = [32]byte{}
	}
	s.finished = !failed
	s.v = sm3IV
	s.buffLen = 0
	s.dataBitsLen = 0
	s.tooLong = false
	clear(s.buff[:])
}

// sum pads the buffered data and writes the digest to out. The chaining value is
// left in an unusable state; the caller resets or discards the instance.
func (s *SM3) sum(out *[32]byte) {
	n := s.buffLen
	s.buff[n] = 0x80
	n++
	if n > sm3BlockSize-8 {
		clear(s.buff[n:])
		sm3Blocks(&s.v, s.buff[:])
		n = 0
	}
	clear(s.buff[n : sm3BlockSize-8])
	binary.BigEndian.PutUint64(s.buff[sm3BlockSize-8:], s.dataBitsLen)
	sm3Blocks(&s.v, s.buff[:])

	for i, v := range s.v {
		binary.BigEndian.PutUint32(out[i*4:], v)
	}
}

// HashBytes returns the 32-byte digest computed by the last Finish, or all zeros if
// Finish has not been called.
func (s *SM3) HashBytes() [32]byte {
	if s == nil {
		return [32]byte{}
	}
	return s.hashBytes
}

// HashHexUpper returns the digest computed by the last Finish as an uppercase hex
// string, or an empty string if Finish has not been called.
func (s *SM3) HashHexUpper() string {
	if s == nil || !s.finished {
		return ""
	}
	out := make([]byte, 64)
	encodeHexTo(out, s.hashBytes[:], upperHex)
	return bytesAsString(out)
}

// sm3Blocks runs the compression function over whole 64-byte blocks. Rounds are written
// out four at a time with the working variables renamed instead of moved.
func sm3Blocks(v *[8]uint32, p []byte) {
	h0, h1, h2, h3, h4, h5, h6, h7 := v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]
	var w [68]uint32

	for ; len(p) >= sm3BlockSize; p = p[sm3BlockSize:] {
		block := p[:sm3BlockSize]
		for j := 0; j < 16; j++ {
			w[j] = binary.BigEndian.Uint32(block[j*4:])
		}
		for j := 16; j < 68; j++ {
			x := w[j-16] ^ w[j-9] ^ bits.RotateLeft32(w[j-3], 15)
			w[j] = x ^ bits.RotateLeft32(x, 15) ^ bits.RotateLeft32(x, 23) ^
				bits.RotateLeft32(w[j-13], 7) ^ w[j-6]
		}

		a, b, c, d, e, f, g, h := h0, h1, h2, h3, h4, h5, h6, h7
		var r, ss1, tt uint32

		for j := 0; j < 16; j += 4 {
			r = bits.RotateLeft32(a, 12)
			ss1 = bits.RotateLeft32(r+e+sm3T[j], 7)
			d += (a ^ b ^ c) + (ss1 ^ r) + (w[j] ^ w[j+4])
			tt = (e ^ f ^ g) + h + ss1 + w[j]
			b = bits.RotateLeft32(b, 9)
			f = bits.RotateLeft32(f, 19)
			h = tt ^ bits.RotateLeft32(tt, 9) ^ bits.RotateLeft32(tt, 17)

			r = bits.RotateLeft32(d, 12)
			ss1 = bits.RotateLeft32(r+h+sm3T[j+1], 7)
			c += (d ^ a ^ b) + (ss1 ^ r) + (w[j+1] ^ w[j+5])
			tt = (h ^ e ^ f) + g + ss1 + w[j+1]
			a = bits.RotateLeft32(a, 9)
			e = bits.RotateLeft32(e, 19)
			g = tt ^ bits.RotateLeft32(tt, 9) ^ bits.RotateLeft32(tt, 17)

			r = bits.RotateLeft32(c, 12)
			ss1 = bits.RotateLeft32(r+g+sm3T[j+2], 7)
			b += (c ^ d ^ a) + (ss1 ^ r) + (w[j+2] ^ w[j+6])
			tt = (g ^ h ^ e) + f + ss1 + w[j+2]
			d = bits.RotateLeft32(d, 9)
			h = bits.RotateLeft32(h, 19)
			f = tt ^ bits.RotateLeft32(tt, 9) ^ bits.RotateLeft32(tt, 17)

			r = bits.RotateLeft32(b, 12)
			ss1 = bits.RotateLeft32(r+f+sm3T[j+3], 7)
			a += (b ^ c ^ d) + (ss1 ^ r) + (w[j+3] ^ w[j+7])
			tt = (f ^ g ^ h) + e + ss1 + w[j+3]
			c = bits.RotateLeft32(c, 9)
			g = bits.RotateLeft32(g, 19)
			e = tt ^ bits.RotateLeft32(tt, 9) ^ bits.RotateLeft32(tt, 17)
		}

		for j := 16; j < 64; j += 4 {
			r = bits.RotateLeft32(a, 12)
			ss1 = bits.RotateLeft32(r+e+sm3T[j], 7)
			d += (a&b | c&(a|b)) + (ss1 ^ r) + (w[j] ^ w[j+4])
			tt = (g ^ e&(f^g)) + h + ss1 + w[j]
			b = bits.RotateLeft32(b, 9)
			f = bits.RotateLeft32(f, 19)
			h = tt ^ bits.RotateLeft32(tt, 9) ^ bits.RotateLeft32(tt, 17)

			r = bits.RotateLeft32(d, 12)
			ss1 = bits.RotateLeft32(r+h+sm3T[j+1], 7)
			c += (d&a | b&(d|a)) + (ss1 ^ r) + (w[j+1] ^ w[j+5])
			tt = (f ^ h&(e^f)) + g + ss1 + w[j+1]
			a = bits.RotateLeft32(a, 9)
			e = bits.RotateLeft32(e, 19)
			g = tt ^ bits.RotateLeft32(tt, 9) ^ bits.RotateLeft32(tt, 17)

			r = bits.RotateLeft32(c, 12)
			ss1 = bits.RotateLeft32(r+g+sm3T[j+2], 7)
			b += (c&d | a&(c|d)) + (ss1 ^ r) + (w[j+2] ^ w[j+6])
			tt = (e ^ g&(h^e)) + f + ss1 + w[j+2]
			d = bits.RotateLeft32(d, 9)
			h = bits.RotateLeft32(h, 19)
			f = tt ^ bits.RotateLeft32(tt, 9) ^ bits.RotateLeft32(tt, 17)

			r = bits.RotateLeft32(b, 12)
			ss1 = bits.RotateLeft32(r+f+sm3T[j+3], 7)
			a += (b&c | d&(b|c)) + (ss1 ^ r) + (w[j+3] ^ w[j+7])
			tt = (h ^ f&(g^h)) + e + ss1 + w[j+3]
			c = bits.RotateLeft32(c, 9)
			g = bits.RotateLeft32(g, 19)
			e = tt ^ bits.RotateLeft32(tt, 9) ^ bits.RotateLeft32(tt, 17)
		}

		h0 ^= a
		h1 ^= b
		h2 ^= c
		h3 ^= d
		h4 ^= e
		h5 ^= f
		h6 ^= g
		h7 ^= h
	}

	v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7] = h0, h1, h2, h3, h4, h5, h6, h7
}
