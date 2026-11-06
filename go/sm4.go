package smx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
)

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

const sm4BlockSize = 16

var (
	// errSM4Decrypt is the single error for every malformed ciphertext: bad hex, bad
	// length and bad padding cannot be told apart, which denies a padding oracle its signal.
	errSM4Decrypt = errors.New("sm4: decryption failed")

	errSM4KeyNotSet = errors.New("sm4: key and IV must be set, 16 bytes each")
	errSM4TooLong   = errors.New("sm4: plaintext too long")
)

// SM4 implements the SM4 block cipher with CBC mode and PKCS#7 padding.
//
// SECURITY: CBC alone gives confidentiality only, with no integrity. Anyone able to
// alter a ciphertext can make it decrypt to something else, and if they can observe
// whether decryption succeeded they may recover plaintext. Authenticate ciphertexts
// separately (encrypt-then-MAC or a signature) before calling Decrypt.
//
// SECURITY: the IV given to SetKey is used for every Encrypt call, as the wire format
// of this library requires, so equal plaintexts encrypt identically and shared prefixes
// are visible. Call SetKey with a fresh random IV for each message, and never reuse a
// key and IV pair for different messages.
//
// SECURITY: this SM4 uses secret-indexed table lookups (see sm4SBox) and is not
// cache-timing resistant. Use the security branch of this repository where an attacker
// may share the CPU or its caches.
//
// After SetKey, Encrypt and Decrypt only read the instance, so they may run concurrently.
// SetKey must not run concurrently with them.
//
// Every key lives behind a pointer, so fmt prints only an address even for an SM4 value in
// an unexported field of a caller's struct, where it cannot call Format. A value copied
// before a later SetKey stops working rather than silently using a wiped key.
type SM4 struct {
	keys *sm4Keys
}

type sm4Keys struct {
	rk  [32]uint32 // encryption round keys
	drk [32]uint32 // decryption round keys, rk reversed
	iv  [16]byte
	set bool
}

// keyed returns the key material, or nil if no valid key is set.
func (s *SM4) keyed() *sm4Keys {
	if s == nil || s.keys == nil || !s.keys.set {
		return nil
	}
	return s.keys
}

// NewSM4 creates a new SM4 instance. It cannot encrypt or decrypt until a key is set.
func NewSM4() *SM4 {
	return &SM4{}
}

// SetKey sets the key and IV, which must be exactly 16 bytes each. On any other size
// the instance is cleared, so Encrypt and Decrypt then fail instead of running with a
// weak key. Use TrySetKey to see the failure immediately.
func (s *SM4) SetKey(key, iv []byte) {
	// The error stays observable through Encrypt and Decrypt.
	_ = s.TrySetKey(key, iv)
}

// TrySetKey sets the key and IV, which must be exactly 16 bytes each, and reports an
// error on any other size. A failure leaves the instance with no key.
func (s *SM4) TrySetKey(key, iv []byte) error {
	if s == nil {
		return errSM4KeyNotSet
	}
	if s.keys != nil {
		*s.keys = sm4Keys{}
		s.keys = nil
	}
	if len(key) != sm4BlockSize || len(iv) != sm4BlockSize {
		return errSM4KeyNotSet
	}
	keys := new(sm4Keys)
	keys.expand(key)
	copy(keys.iv[:], iv)
	keys.set = true
	s.keys = keys
	return nil
}

// Format keeps key material out of logs: every fmt verb prints a placeholder.
func (s SM4) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "SM4{redacted}")
}

// sm4SBox is the S-box from GB/T 32907.
//
// SECURITY: on this branch SM4 indexes tables with secret bytes, as OpenSSL and
// BouncyCastle do. That is fast but not cache-timing resistant: code sharing the CPU
// cache can learn key and data bits. The security branch of this repository keeps the
// constant-time SM4 (hardware AES/GFNI paths and a Boolean-circuit S-box only).
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

// sm4Tables holds the S-box combined with the linear transforms. t[i][x] is L applied to
// S(x) placed in byte i of the word, counting from the most significant, so one round
// is four lookups and three XORs. k does the same with the key schedule's L'.
type sm4Tables struct {
	t [4][256]uint32
	k [4][256]uint32
}

var sm4Tab = sm4MakeTables()

func sm4MakeTables() *sm4Tables {
	tab := new(sm4Tables)
	for x := 0; x < 256; x++ {
		for i := 0; i < 4; i++ {
			b := uint32(sm4SBox[x]) << (24 - 8*uint(i))
			tab.t[i][x] = b ^ bits.RotateLeft32(b, 2) ^ bits.RotateLeft32(b, 10) ^
				bits.RotateLeft32(b, 18) ^ bits.RotateLeft32(b, 24)
			tab.k[i][x] = b ^ bits.RotateLeft32(b, 13) ^ bits.RotateLeft32(b, 23)
		}
	}
	return tab
}

// expand computes the encryption round keys and their reverse for decryption.
func (s *sm4Keys) expand(key []byte) {
	k0 := binary.BigEndian.Uint32(key[0:]) ^ sm4FK[0]
	k1 := binary.BigEndian.Uint32(key[4:]) ^ sm4FK[1]
	k2 := binary.BigEndian.Uint32(key[8:]) ^ sm4FK[2]
	k3 := binary.BigEndian.Uint32(key[12:]) ^ sm4FK[3]

	k := &sm4Tab.k
	tp := func(x uint32) uint32 {
		return k[0][x>>24] ^ k[1][byte(x>>16)] ^ k[2][byte(x>>8)] ^ k[3][byte(x)]
	}
	for i := 0; i < 32; i += 4 {
		k0 ^= tp(k1 ^ k2 ^ k3 ^ sm4CK[i])
		k1 ^= tp(k2 ^ k3 ^ k0 ^ sm4CK[i+1])
		k2 ^= tp(k3 ^ k0 ^ k1 ^ sm4CK[i+2])
		k3 ^= tp(k0 ^ k1 ^ k2 ^ sm4CK[i+3])
		s.rk[i], s.rk[i+1], s.rk[i+2], s.rk[i+3] = k0, k1, k2, k3
		s.drk[31-i], s.drk[30-i], s.drk[29-i], s.drk[28-i] = k0, k1, k2, k3
	}
}

//go:generate go run sm4_decrypt_gen.go

// sm4EncryptWords runs the 32 rounds over one block held in four words.
func sm4EncryptWords(rk *[32]uint32, x0, x1, x2, x3 uint32) (uint32, uint32, uint32, uint32) {
	t := &sm4Tab.t
	for i := 0; i < 32; i += 4 {
		x := x1 ^ x2 ^ x3 ^ rk[i]
		x0 ^= t[0][x>>24] ^ t[1][byte(x>>16)] ^ t[2][byte(x>>8)] ^ t[3][byte(x)]
		x = x2 ^ x3 ^ x0 ^ rk[i+1]
		x1 ^= t[0][x>>24] ^ t[1][byte(x>>16)] ^ t[2][byte(x>>8)] ^ t[3][byte(x)]
		x = x3 ^ x0 ^ x1 ^ rk[i+2]
		x2 ^= t[0][x>>24] ^ t[1][byte(x>>16)] ^ t[2][byte(x>>8)] ^ t[3][byte(x)]
		x = x0 ^ x1 ^ x2 ^ rk[i+3]
		x3 ^= t[0][x>>24] ^ t[1][byte(x>>16)] ^ t[2][byte(x>>8)] ^ t[3][byte(x)]
	}
	return x3, x2, x1, x0
}

// sm4CBCEncrypt encrypts whole blocks of buf in place. CBC encryption is serial, and
// one table-driven block at a time beats the hardware paths here on every CPU measured.
func sm4CBCEncrypt(rk *[32]uint32, iv *[16]byte, buf []byte) {
	c0 := binary.BigEndian.Uint32(iv[0:])
	c1 := binary.BigEndian.Uint32(iv[4:])
	c2 := binary.BigEndian.Uint32(iv[8:])
	c3 := binary.BigEndian.Uint32(iv[12:])
	for ; len(buf) >= sm4BlockSize; buf = buf[sm4BlockSize:] {
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

// sm4PaddedSize returns the length of the padded plaintext for n input bytes, and
// false if its hex form would not fit in an int.
func sm4PaddedSize(n int) (int, bool) {
	if n < 0 || n > (math.MaxInt-2*sm4BlockSize)/2 {
		return 0, false
	}
	return n + sm4BlockSize - n%sm4BlockSize, true
}

// Encrypt encrypts a plaintext string and returns ciphertext as hex. See the SM4 type
// for the IV and integrity requirements.
func (s *SM4) Encrypt(plaintext string) (string, error) {
	keys := s.keyed()
	if keys == nil {
		return "", errSM4KeyNotSet
	}
	size, ok := sm4PaddedSize(len(plaintext))
	if !ok {
		return "", errSM4TooLong
	}
	padLen := size - len(plaintext)

	// One buffer holds both forms: the ciphertext is built in the upper half and then
	// expanded to hex from the front.
	out := make([]byte, 2*size)
	raw := out[size:]
	copy(raw, plaintext)
	for i := len(plaintext); i < size; i++ {
		raw[i] = byte(padLen)
	}
	sm4CBCEncrypt(&keys.rk, &keys.iv, raw)
	encodeHexTo(out, raw, lowerHex)
	return bytesAsString(out), nil
}

// Decrypt decrypts a canonical (lowercase) hex ciphertext string and returns plaintext.
// Every malformed ciphertext gets the same error. A successful Decrypt does not show the
// ciphertext is authentic; see the SM4 type.
//
// The string holds the plaintext bytes exactly as decrypted: there is no UTF-8 step, so
// binary plaintext is safe and nothing here runs only on valid padding. A caller that
// validates the result, and so spends time only after success, adds a timing signal of
// its own; authenticate ciphertexts first. Timing still depends on the ciphertext length.
func (s *SM4) Decrypt(ciphertext string) (string, error) {
	keys := s.keyed()
	if keys == nil {
		return "", errSM4KeyNotSet
	}
	buf, err := hexToBytes(ciphertext)
	if err != nil || len(buf) == 0 || len(buf)%sm4BlockSize != 0 {
		return "", errSM4Decrypt
	}
	sm4CBCDecrypt(&keys.drk, &keys.iv, buf)
	plain, valid := sm4Unpad(buf)
	if !valid {
		return "", errSM4Decrypt
	}
	return bytesAsString(plain), nil
}

// sm4Unpad validates the padding and returns the plaintext. It does the same work on both
// outcomes: the whole buffer goes through maskBytes, which keeps it for valid padding and
// erases it otherwise. Erasing only on failure would be a padding oracle.
func sm4Unpad(buf []byte) ([]byte, bool) {
	padLen, good := pkcs7Check(buf)
	maskBytes(buf, good)
	return buf[:len(buf)-int(uint64(padLen)&good)], good != 0
}

// maskBytes ANDs every byte of b with mask, which is all ones or zero. No branch and no
// memory access depends on the mask.
func maskBytes(b []byte, mask uint64) {
	for len(b) >= 8 {
		binary.LittleEndian.PutUint64(b, binary.LittleEndian.Uint64(b)&mask)
		b = b[8:]
	}
	for i := range b {
		b[i] &= byte(mask)
	}
}

// pkcs7Check returns the padding length of a non-empty whole-block buffer, and a mask
// that is all ones if the padding is valid and zero otherwise. It always reads the last
// 16 bytes and combines the checks with masks, so its timing does not depend on the
// padding.
func pkcs7Check(input []byte) (uint32, uint64) {
	tail := input[len(input)-sm4BlockSize:]
	padLen := uint32(tail[sm4BlockSize-1])

	// The top bit of bad gets set for any invalid value.
	bad := padLen - 1          // wraps for padLen == 0
	bad |= uint32(16) - padLen // wraps for padLen > 16
	for i := uint32(0); i < sm4BlockSize; i++ {
		// inPad has its top bit set when this byte, i from the end, is in the padding.
		inPad := i - padLen
		mismatch := uint32(tail[sm4BlockSize-1-i]) ^ padLen
		// A non-zero mismatch wraps to set the top bit.
		bad |= (uint32(0) - mismatch) & inPad
	}
	return padLen, uint64(bad>>31) - 1
}
