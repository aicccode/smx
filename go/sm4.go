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
// After SetKey, Encrypt and Decrypt only read the instance, so they may run concurrently.
// SetKey must not run concurrently with them.
type SM4 struct {
	rk     [32]uint32 // encryption round keys
	drk    [32]uint32 // decryption round keys, rk reversed
	iv     [16]byte
	keySet bool
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
	*s = SM4{}
	if len(key) != sm4BlockSize || len(iv) != sm4BlockSize {
		return errSM4KeyNotSet
	}
	s.expandKey(key)
	copy(s.iv[:], iv)
	s.keySet = true
	return nil
}

// Format keeps key material out of logs: every fmt verb prints a placeholder.
func (s SM4) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "SM4{redacted}")
}

// sm4Tau applies the S-box to the four bytes of a. It spreads each input bit to the low
// bit of its byte, so the circuit computes four S-boxes side by side.
func sm4Tau(a uint32) uint32 {
	const low = 0x01010101
	v := uint64(a)
	y0, y1, y2, y3, y4, y5, y6, y7 := sm4SBoxCircuit(v&low, (v>>1)&low, (v>>2)&low, (v>>3)&low,
		(v>>4)&low, (v>>5)&low, (v>>6)&low, (v>>7)&low)
	return uint32(y0&low | (y1&low)<<1 | (y2&low)<<2 | (y3&low)<<3 |
		(y4&low)<<4 | (y5&low)<<5 | (y6&low)<<6 | (y7&low)<<7)
}

// expandKey computes the round keys. It uses the circuit on every path, so the key
// schedule makes no secret-indexed memory access.
func (s *SM4) expandKey(key []byte) {
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

// sm4TPrime is the key schedule's transform: the S-box followed by L'.
func sm4TPrime(a uint32) uint32 {
	b := sm4Tau(a)
	return b ^ bits.RotateLeft32(b, 13) ^ bits.RotateLeft32(b, 23)
}

// sm4RoundT is the round transform T: the S-box followed by L.
func sm4RoundT(x uint32) uint32 {
	b := sm4Tau(x)
	return b ^ bits.RotateLeft32(b, 2) ^ bits.RotateLeft32(b, 10) ^
		bits.RotateLeft32(b, 18) ^ bits.RotateLeft32(b, 24)
}

// sm4EncryptWords runs the 32 rounds over one block held in four words.
func sm4EncryptWords(rk *[32]uint32, x0, x1, x2, x3 uint32) (uint32, uint32, uint32, uint32) {
	for i := 0; i < 32; i += 4 {
		x0 ^= sm4RoundT(x1 ^ x2 ^ x3 ^ rk[i])
		x1 ^= sm4RoundT(x2 ^ x3 ^ x0 ^ rk[i+1])
		x2 ^= sm4RoundT(x3 ^ x0 ^ x1 ^ rk[i+2])
		x3 ^= sm4RoundT(x0 ^ x1 ^ x2 ^ rk[i+3])
	}
	return x3, x2, x1, x0
}

const sm4BatchBlocks = 16

// sm4Swap exchanges the bits selected by mask in b with those shifted by n in a.
func sm4Swap(a, b, mask uint64, n uint) (uint64, uint64) {
	t := ((a >> n) ^ b) & mask
	return a ^ t<<n, b ^ t
}

// sm4Transpose8 transposes the 8x8 bit matrix formed by the same byte of each word,
// for all eight byte positions at once. It is its own inverse.
func sm4Transpose8(x *[8]uint64) {
	const (
		m4 = 0x0F0F0F0F0F0F0F0F
		m2 = 0x3333333333333333
		m1 = 0x5555555555555555
	)
	x[0], x[4] = sm4Swap(x[0], x[4], m4, 4)
	x[1], x[5] = sm4Swap(x[1], x[5], m4, 4)
	x[2], x[6] = sm4Swap(x[2], x[6], m4, 4)
	x[3], x[7] = sm4Swap(x[3], x[7], m4, 4)
	x[0], x[2] = sm4Swap(x[0], x[2], m2, 2)
	x[1], x[3] = sm4Swap(x[1], x[3], m2, 2)
	x[4], x[6] = sm4Swap(x[4], x[6], m2, 2)
	x[5], x[7] = sm4Swap(x[5], x[7], m2, 2)
	x[0], x[1] = sm4Swap(x[0], x[1], m1, 1)
	x[2], x[3] = sm4Swap(x[2], x[3], m1, 1)
	x[4], x[5] = sm4Swap(x[4], x[5], m1, 1)
	x[6], x[7] = sm4Swap(x[6], x[7], m1, 1)
}

// rotl32x2 rotates both 32-bit lanes of v left by n.
func rotl32x2(v uint64, n uint) uint64 {
	lowLanes := uint64(0xFFFFFFFF>>(32-n)) * 0x0000000100000001
	return (v<<n)&^lowLanes | (v>>(32-n))&lowLanes
}

// sm4CryptBatch runs the rounds over sm4BatchBlocks blocks of buf in place. Each uint64
// holds a word of two blocks, so one circuit evaluation does 64 S-boxes.
func sm4CryptBatch(rk *[32]uint32, buf *[sm4BatchBlocks * sm4BlockSize]byte) {
	var state [4][8]uint64
	for b := 0; b < sm4BatchBlocks; b++ {
		for w := 0; w < 4; w++ {
			v := uint64(binary.BigEndian.Uint32(buf[b*16+w*4:]))
			state[w][b/2] |= v << (32 * uint(b&1))
		}
	}

	var slices [8]uint64
	for r := 0; r < 32; r++ {
		key := uint64(rk[r]) * 0x0000000100000001
		s0, s1, s2, s3 := &state[r&3], &state[(r+1)&3], &state[(r+2)&3], &state[(r+3)&3]
		for k := range slices {
			slices[k] = s1[k] ^ s2[k] ^ s3[k] ^ key
		}
		sm4Transpose8(&slices)
		slices[0], slices[1], slices[2], slices[3], slices[4], slices[5], slices[6], slices[7] =
			sm4SBoxCircuit(slices[0], slices[1], slices[2], slices[3], slices[4], slices[5], slices[6], slices[7])
		sm4Transpose8(&slices)
		for k, b := range slices {
			s0[k] ^= b ^ rotl32x2(b, 2) ^ rotl32x2(b, 10) ^ rotl32x2(b, 18) ^ rotl32x2(b, 24)
		}
	}

	for b := 0; b < sm4BatchBlocks; b++ {
		for w := 0; w < 4; w++ {
			v := uint32(state[3-w][b/2] >> (32 * uint(b&1)))
			binary.BigEndian.PutUint32(buf[b*16+w*4:], v)
		}
	}
	state = [4][8]uint64{}
	slices = [8]uint64{}
}

// sm4CBCEncryptGeneric encrypts whole blocks of buf in place with the portable code,
// which has no secret-dependent memory access or branch.
func sm4CBCEncryptGeneric(rk *[32]uint32, iv *[16]byte, buf []byte) {
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

// sm4CBCDecryptGeneric decrypts whole blocks of buf in place with the portable code,
// which has no secret-dependent memory access or branch. Runs of blocks go through the
// bitsliced batch; the batch is not worth its cost below about five blocks.
func sm4CBCDecryptGeneric(drk *[32]uint32, iv *[16]byte, buf []byte) {
	const batchBytes = sm4BatchBlocks * sm4BlockSize
	var batch, saved [batchBytes]byte
	var prev [sm4BlockSize]byte
	copy(prev[:], iv[:])

	for len(buf) >= 5*sm4BlockSize {
		n := copy(batch[:], buf)
		clear(batch[n:])
		copy(saved[:], batch[:])
		sm4CryptBatch(drk, &batch)
		for i := range prev {
			batch[i] ^= prev[i]
		}
		for i := sm4BlockSize; i < n; i++ {
			batch[i] ^= saved[i-sm4BlockSize]
		}
		copy(prev[:], saved[n-sm4BlockSize:n])
		copy(buf, batch[:n])
		buf = buf[n:]
	}
	wipeBytes(batch[:])

	p0 := binary.BigEndian.Uint32(prev[0:])
	p1 := binary.BigEndian.Uint32(prev[4:])
	p2 := binary.BigEndian.Uint32(prev[8:])
	p3 := binary.BigEndian.Uint32(prev[12:])
	for ; len(buf) >= sm4BlockSize; buf = buf[sm4BlockSize:] {
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
	if s == nil || !s.keySet {
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
	sm4CBCEncrypt(&s.rk, &s.iv, raw)
	encodeHexTo(out, raw, lowerHex)
	return bytesAsString(out), nil
}

// Decrypt decrypts a hex ciphertext string and returns plaintext. Every malformed
// ciphertext gets the same error. A successful Decrypt does not show the ciphertext is
// authentic; see the SM4 type.
func (s *SM4) Decrypt(ciphertext string) (string, error) {
	if s == nil || !s.keySet {
		return "", errSM4KeyNotSet
	}
	buf, err := hexToBytes(ciphertext)
	if err != nil || len(buf) == 0 || len(buf)%sm4BlockSize != 0 {
		return "", errSM4Decrypt
	}
	sm4CBCDecrypt(&s.drk, &s.iv, buf)
	padLen, valid := pkcs7PadLen(buf)
	if !valid {
		wipeBytes(buf)
		return "", errSM4Decrypt
	}
	return bytesAsString(buf[:len(buf)-padLen]), nil
}

// pkcs7PadLen returns the padding length of a non-empty whole-block buffer. It always
// reads the last 16 bytes and combines the checks with masks, so its timing does
// not depend on the padding. The caller may branch only on the final result.
func pkcs7PadLen(input []byte) (int, bool) {
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
	return int(padLen), bad>>31 == 0
}
