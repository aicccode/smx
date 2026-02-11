package smx

import "math/bits"

var sm3IV = [8]uint32{
	0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
	0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
}

// SM3 implements the SM3 cryptographic hash function.
type SM3 struct {
	v           [8]uint32
	buff        [64]byte
	buffLen     int
	dataBitsLen uint64
	hashBytes   [32]byte
	hashHexStr  string
}

// NewSM3 creates a new SM3 hash instance.
func NewSM3() *SM3 {
	s := &SM3{}
	s.v = sm3IV
	return s
}

func (s *SM3) reset() {
	s.v = sm3IV
	s.buffLen = 0
	s.dataBitsLen = 0
}

// UpdateByte feeds a single byte into the hash.
func (s *SM3) UpdateByte(b byte) {
	s.buff[s.buffLen] = b
	s.buffLen++
	s.dataBitsLen += 8
	if s.buffLen == 64 {
		block := s.buff
		s.processBlock(block[:])
		s.buffLen = 0
	}
}

// Update feeds a byte slice into the hash.
func (s *SM3) Update(data []byte) {
	for _, b := range data {
		s.UpdateByte(b)
	}
}

// Finish finalizes the hash computation (padding + final blocks).
func (s *SM3) Finish() {
	end := make([]byte, s.buffLen)
	copy(end, s.buff[:s.buffLen])

	blockLenBits := int32(s.buffLen) * 8
	dataLenBits := int32(s.dataBitsLen & 0xFFFFFFFF)

	fillZeroLenBits := (512 - (blockLenBits+65)%512) - 7
	allLenBits := fillZeroLenBits + blockLenBits + 65 + 7
	allByteLen := allLenBits / 8

	buf := make([]byte, allByteLen)
	for i := int32(0); i < allByteLen; i++ {
		idx := int(i)
		if idx < len(end) {
			buf[idx] = end[idx]
		} else if idx == len(end) {
			buf[idx] = 0x80
		} else if i > allByteLen-5 {
			shift := (allByteLen - i - 1) * 8
			val := (dataLenBits >> shift) & 0xFF
			buf[idx] = byte(val)
		}
	}

	blocks := allLenBits / 512
	for i := int32(0); i < blocks; i++ {
		start := int(i * 64)
		s.processBlock(buf[start : start+64])
	}

	s.generateHashString()
	s.reset()
}

// HashBytes returns the computed 32-byte hash.
func (s *SM3) HashBytes() [32]byte {
	return s.hashBytes
}

// HashHexUpper returns the computed hash as an uppercase hex string.
func (s *SM3) HashHexUpper() string {
	return s.hashHexStr
}

func (s *SM3) generateHashString() {
	var out [32]byte
	off := 0
	for _, v := range s.v {
		out[off] = byte(v >> 24)
		out[off+1] = byte(v >> 16)
		out[off+2] = byte(v >> 8)
		out[off+3] = byte(v)
		off += 4
	}
	s.hashBytes = out

	const hexUpper = "0123456789ABCDEF"
	buf := make([]byte, 64)
	for i, b := range out {
		buf[i*2] = hexUpper[b>>4]
		buf[i*2+1] = hexUpper[b&0x0F]
	}
	s.hashHexStr = string(buf)
}

func (s *SM3) processBlock(block []byte) {
	// Message expansion
	var w [68]uint32
	for j := 0; j < 16; j++ {
		off := j * 4
		w[j] = uint32(block[off])<<24 | uint32(block[off+1])<<16 |
			uint32(block[off+2])<<8 | uint32(block[off+3])
	}
	for j := 16; j < 68; j++ {
		r15 := bits.RotateLeft32(w[j-3], 15)
		r7 := bits.RotateLeft32(w[j-13], 7)
		w[j] = sm3P1(w[j-16]^w[j-9]^r15) ^ r7 ^ w[j-6]
	}
	var w2 [64]uint32
	for j := 0; j < 64; j++ {
		w2[j] = w[j] ^ w[j+4]
	}

	// Compression
	a, b, c, d := s.v[0], s.v[1], s.v[2], s.v[3]
	e, f, g, h := s.v[4], s.v[5], s.v[6], s.v[7]

	for j := 0; j < 64; j++ {
		a12 := bits.RotateLeft32(a, 12)
		var tj uint32
		if j < 16 {
			tj = bits.RotateLeft32(0x79CC4519, j)
		} else {
			tj = bits.RotateLeft32(0x7A879D8A, j%32)
		}
		ss := a12 + e + tj
		ss1 := bits.RotateLeft32(ss, 7)
		ss2 := ss1 ^ a12

		var tt1, tt2 uint32
		if j < 16 {
			tt1 = (a ^ b ^ c) + d + ss2 + w2[j]
			tt2 = (e ^ f ^ g) + h + ss1 + w[j]
		} else {
			tt1 = sm3FF1(a, b, c) + d + ss2 + w2[j]
			tt2 = sm3GG1(e, f, g) + h + ss1 + w[j]
		}
		d = c
		c = bits.RotateLeft32(b, 9)
		b = a
		a = tt1
		h = g
		g = bits.RotateLeft32(f, 19)
		f = e
		e = sm3P0(tt2)
	}

	s.v[0] ^= a
	s.v[1] ^= b
	s.v[2] ^= c
	s.v[3] ^= d
	s.v[4] ^= e
	s.v[5] ^= f
	s.v[6] ^= g
	s.v[7] ^= h
}

func sm3FF1(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
func sm3GG1(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
func sm3P0(x uint32) uint32        { return x ^ bits.RotateLeft32(x, 9) ^ bits.RotateLeft32(x, 17) }
func sm3P1(x uint32) uint32        { return x ^ bits.RotateLeft32(x, 15) ^ bits.RotateLeft32(x, 23) }
