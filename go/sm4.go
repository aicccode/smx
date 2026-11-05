package smx

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

var sm4SBox = [256]byte{
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
}

var sm4FK = [4]uint32{0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc}

var sm4CK = [32]uint32{
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
}

// sm4T0..sm4T3 combine the S-box with the linear transform L, one table per input
// byte, for the portable code path. Caveat: these lookups are indexed by secret data, so
// that path is not protected against cache-timing attacks, and tables of 4 KiB rather
// than the 256-byte S-box give a local attacker somewhat more signal. They are used only
// where no hardware path exists; see sm4_amd64.go.
var sm4T0, sm4T1, sm4T2, sm4T3 = func() (t0, t1, t2, t3 [256]uint32) {
	for i, sb := range sm4SBox {
		b := uint32(sb)
		v := b ^ bits.RotateLeft32(b, 2) ^ bits.RotateLeft32(b, 10) ^
			bits.RotateLeft32(b, 18) ^ bits.RotateLeft32(b, 24)
		t3[i] = v
		t2[i] = bits.RotateLeft32(v, 8)
		t1[i] = bits.RotateLeft32(v, 16)
		t0[i] = bits.RotateLeft32(v, 24)
	}
	return t0, t1, t2, t3
}()

// SM4 implements the SM4 block cipher with CBC mode and PKCS#7 padding. After SetKey,
// Encrypt and Decrypt only read the instance, so they are safe for concurrent use.
type SM4 struct {
	rk  [32]uint32 // encryption round keys
	drk [32]uint32 // decryption round keys, rk reversed
	iv  [16]byte
}

// NewSM4 creates a new SM4 instance.
func NewSM4() *SM4 {
	return &SM4{}
}

// SetKey sets the encryption key and IV. Non-16-byte keys/IVs are hashed via SM3.
func (s *SM4) SetKey(key, iv []byte) {
	keyBytes := sm4PrepareKey(key)
	s.iv = sm4PrepareKey(iv)
	s.expandKey(&keyBytes)
}

// sm4PrepareKey returns 16-byte input unchanged. Other input is replaced by the first
// 16 characters of the uppercase hex of its SM3 digest, the format this library has
// always used.
func sm4PrepareKey(input []byte) [16]byte {
	var out [16]byte
	if len(input) == 16 {
		copy(out[:], input)
		return out
	}
	var h SM3
	h.v = sm3IV
	h.Update(input)
	var digest [32]byte
	h.sum(&digest)
	encodeHexTo(out[:], digest[:8], 0x07)
	return out
}

func (s *SM4) expandKey(key *[16]byte) {
	k0 := binary.BigEndian.Uint32(key[0:]) ^ sm4FK[0]
	k1 := binary.BigEndian.Uint32(key[4:]) ^ sm4FK[1]
	k2 := binary.BigEndian.Uint32(key[8:]) ^ sm4FK[2]
	k3 := binary.BigEndian.Uint32(key[12:]) ^ sm4FK[3]

	for i := 0; i < 32; i += 4 {
		k0 ^= sm4TPrime(k1 ^ k2 ^ k3 ^ sm4CK[i])
		k1 ^= sm4TPrime(k2 ^ k3 ^ k0 ^ sm4CK[i+1])
		k2 ^= sm4TPrime(k3 ^ k0 ^ k1 ^ sm4CK[i+2])
		k3 ^= sm4TPrime(k0 ^ k1 ^ k2 ^ sm4CK[i+3])
		s.rk[i], s.rk[i+1], s.rk[i+2], s.rk[i+3] = k0, k1, k2, k3
		s.drk[31-i], s.drk[30-i], s.drk[29-i], s.drk[28-i] = k0, k1, k2, k3
	}
}

// sm4TPrime is the key schedule's transform: the S-box followed by L'. The key schedule
// uses the plain S-box on every path, so its table accesses are secret indexed.
func sm4TPrime(a uint32) uint32 {
	b := uint32(sm4SBox[byte(a>>24)])<<24 | uint32(sm4SBox[byte(a>>16)])<<16 |
		uint32(sm4SBox[byte(a>>8)])<<8 | uint32(sm4SBox[byte(a)])
	return b ^ bits.RotateLeft32(b, 13) ^ bits.RotateLeft32(b, 23)
}

// sm4Round is the round transform T using the combined tables.
func sm4Round(x uint32) uint32 {
	return sm4T0[x>>24] ^ sm4T1[byte(x>>16)] ^ sm4T2[byte(x>>8)] ^ sm4T3[byte(x)]
}

// sm4EncryptWords runs the 32 rounds over one block held in four words.
func sm4EncryptWords(rk *[32]uint32, x0, x1, x2, x3 uint32) (uint32, uint32, uint32, uint32) {
	for i := 0; i < 32; i += 4 {
		x0 ^= sm4Round(x1 ^ x2 ^ x3 ^ rk[i])
		x1 ^= sm4Round(x2 ^ x3 ^ x0 ^ rk[i+1])
		x2 ^= sm4Round(x3 ^ x0 ^ x1 ^ rk[i+2])
		x3 ^= sm4Round(x0 ^ x1 ^ x2 ^ rk[i+3])
	}
	return x3, x2, x1, x0
}

// sm4CBCEncryptGeneric encrypts whole blocks of buf in place with the portable code.
func sm4CBCEncryptGeneric(rk *[32]uint32, iv *[16]byte, buf []byte) {
	c0 := binary.BigEndian.Uint32(iv[0:])
	c1 := binary.BigEndian.Uint32(iv[4:])
	c2 := binary.BigEndian.Uint32(iv[8:])
	c3 := binary.BigEndian.Uint32(iv[12:])
	for ; len(buf) >= 16; buf = buf[16:] {
		c0, c1, c2, c3 = sm4EncryptWords(rk,
			c0^binary.BigEndian.Uint32(buf[0:]),
			c1^binary.BigEndian.Uint32(buf[4:]),
			c2^binary.BigEndian.Uint32(buf[8:]),
			c3^binary.BigEndian.Uint32(buf[12:]))
		binary.BigEndian.PutUint32(buf[0:], c0)
		binary.BigEndian.PutUint32(buf[4:], c1)
		binary.BigEndian.PutUint32(buf[8:], c2)
		binary.BigEndian.PutUint32(buf[12:], c3)
	}
}

// sm4CBCDecryptGeneric decrypts whole blocks of buf in place with the portable code.
func sm4CBCDecryptGeneric(drk *[32]uint32, iv *[16]byte, buf []byte) {
	p0 := binary.BigEndian.Uint32(iv[0:])
	p1 := binary.BigEndian.Uint32(iv[4:])
	p2 := binary.BigEndian.Uint32(iv[8:])
	p3 := binary.BigEndian.Uint32(iv[12:])
	for ; len(buf) >= 16; buf = buf[16:] {
		c0 := binary.BigEndian.Uint32(buf[0:])
		c1 := binary.BigEndian.Uint32(buf[4:])
		c2 := binary.BigEndian.Uint32(buf[8:])
		c3 := binary.BigEndian.Uint32(buf[12:])
		x0, x1, x2, x3 := sm4EncryptWords(drk, c0, c1, c2, c3)
		binary.BigEndian.PutUint32(buf[0:], x0^p0)
		binary.BigEndian.PutUint32(buf[4:], x1^p1)
		binary.BigEndian.PutUint32(buf[8:], x2^p2)
		binary.BigEndian.PutUint32(buf[12:], x3^p3)
		p0, p1, p2, p3 = c0, c1, c2, c3
	}
}

// Encrypt encrypts a plaintext string and returns ciphertext as hex.
func (s *SM4) Encrypt(plaintext string) (string, error) {
	padLen := 16 - len(plaintext)%16
	size := len(plaintext) + padLen

	// One buffer holds both forms: the ciphertext is built in the upper half and then
	// expanded to hex from the front.
	out := make([]byte, 2*size)
	raw := out[size:]
	copy(raw, plaintext)
	for i := len(plaintext); i < size; i++ {
		raw[i] = byte(padLen)
	}
	sm4CBCEncrypt(&s.rk, &s.iv, raw)
	encodeHexTo(out, raw, 0x27)
	return bytesAsString(out), nil
}

// Decrypt decrypts a hex ciphertext string and returns plaintext.
func (s *SM4) Decrypt(ciphertext string) (string, error) {
	buf, err := hexToBytes(ciphertext)
	if err != nil {
		return "", err
	}
	if len(buf)%16 != 0 {
		return "", errors.New("invalid ciphertext length")
	}
	sm4CBCDecrypt(&s.drk, &s.iv, buf)
	plain, err := pkcs7Unpad(buf)
	if err != nil {
		return "", err
	}
	return bytesAsString(plain), nil
}

// pkcs7Unpad strips PKCS#7 padding. Empty input is returned as is.
func pkcs7Unpad(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}
	padLen := int(input[len(input)-1])
	if padLen == 0 || padLen > 16 || padLen > len(input) {
		return nil, errors.New("invalid padding")
	}
	for i := len(input) - padLen; i < len(input); i++ {
		if int(input[i]) != padLen {
			return nil, errors.New("invalid padding")
		}
	}
	return input[:len(input)-padLen], nil
}
