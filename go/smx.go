// Package smx implements the Chinese national cryptographic algorithms SM2 (public
// key), SM3 (hash) and SM4 (block cipher) with no dependencies outside the standard
// library.
//
// # Invalid input
//
// No function panics on any input. Functions that return an error or a bool report
// invalid input that way. Functions whose signature cannot report failure return a
// value that later checks reject: the point at infinity for a point, zero for a number,
// and empty strings for a key pair. Prefer SM2ParsePublicKey, BigInt256ParseHex,
// SM2GenerateKeyPair and (*SM4).TrySetKey, which return errors.
//
// # Security limits
//
// SM4 here is CBC with no integrity; see the SM4 type. Secret-dependent branches and
// memory accesses are avoided by construction and checked in the compiled output, but
// the Go compiler gives no constant-time guarantee. Secrets are overwritten on a
// best-effort basis only: the runtime may copy stacks, and strings cannot be erased.
package smx

import (
	"encoding/binary"
	"errors"
	"runtime"
	"unsafe"
)

// Alphabet offsets for hexSpread.
const (
	lowerHex = 0x27
	upperHex = 0x07
)

// hexSpread turns the four bytes of x into eight ASCII hex digits, most significant
// digit in the top byte. Arithmetic replaces a table lookup, so no memory access
// depends on the value and private keys can pass through it. alphaOffset is 0x27 for
// lowercase digits and 0x07 for uppercase.
func hexSpread(x uint32, alphaOffset uint64) uint64 {
	v := uint64(x)
	v = (v | v<<16) & 0x0000FFFF0000FFFF
	v = (v | v<<8) & 0x00FF00FF00FF00FF
	v = (v | v<<4) & 0x0F0F0F0F0F0F0F0F
	// A nibble above 9 sets bit 4 once 6 has been added to it.
	alpha := ((v + 0x0606060606060606) >> 4) & 0x0101010101010101
	return v + 0x3030303030303030 + alpha*alphaOffset
}

// encodeHexTo writes the hex encoding of src to dst, which must hold 2*len(src) bytes.
// src may be the second half of dst: each input word is read before the output
// that could overlap it is written.
func encodeHexTo(dst, src []byte, alphaOffset uint64) {
	for len(src) >= 4 {
		binary.BigEndian.PutUint64(dst, hexSpread(binary.BigEndian.Uint32(src), alphaOffset))
		dst, src = dst[8:], src[4:]
	}
	for i, b := range src {
		v := uint32(b) << 24
		digits := hexSpread(v, alphaOffset)
		dst[2*i] = byte(digits >> 56)
		dst[2*i+1] = byte(digits >> 48)
	}
}

// bytesAsString returns b as a string without copying. The caller must not modify b
// afterwards.
func bytesAsString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// stringAsBytes returns a read-only view of s. The caller must not modify the result.
func stringAsBytes(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// bytesToHex converts a byte slice to a lowercase hex string.
func bytesToHex(b []byte) string {
	out := make([]byte, 2*len(b))
	encodeHexTo(out, b, lowerHex)
	return bytesAsString(out)
}

var errInvalidHex = errors.New("smx: invalid hex")

// hexDigits8 converts eight ASCII hex digits, the first in the low byte, to four bytes,
// with arithmetic instead of table lookups. The second result has bits set if any
// digit was invalid.
func hexDigits8(v uint64) (uint32, uint64) {
	const (
		ones  = 0x0101010101010101
		highs = 0x8080808080808080
	)
	digit := v ^ (0x30 * ones)                             // 0..9 for '0'..'9'
	alpha := (v | (0x20 * ones)) ^ (0x60 * ones)           // 1..6 for 'a'..'f' and 'A'..'F'
	notDigit := digit + 0x76*ones                          // top bit set above 9
	notAlpha := (alpha + 0x79*ones) | ^(alpha + 0x7F*ones) // top bit set outside 1..6
	invalid := (notDigit&notAlpha | v) & highs

	nibbles := (v & (0x0F * ones)) + 9*((v>>6)&ones)
	w := (nibbles<<4 | nibbles>>8) & 0x00FF00FF00FF00FF
	w = (w | w>>8) & 0x0000FFFF0000FFFF
	return uint32(w | w>>16), invalid
}

// decodeHexInto decodes s into dst, which must hold exactly len(s)/2 bytes, and
// reports whether every digit was valid. The length of s must be even. Validity is
// accumulated rather than tested per digit, so valid input takes a data-independent path.
func decodeHexInto(dst []byte, s string) bool {
	if len(s) != 2*len(dst) {
		return false
	}
	src := stringAsBytes(s)
	var invalid uint64
	for len(dst) >= 4 {
		word, bad := hexDigits8(binary.LittleEndian.Uint64(src))
		invalid |= bad
		binary.LittleEndian.PutUint32(dst, word)
		dst, src = dst[4:], src[8:]
	}
	if len(dst) > 0 {
		// Up to six digits are left: pad them with valid digits.
		tail := [8]byte{'0', '0', '0', '0', '0', '0', '0', '0'}
		copy(tail[:], src)
		word, bad := hexDigits8(binary.LittleEndian.Uint64(tail[:]))
		invalid |= bad
		var out [4]byte
		binary.LittleEndian.PutUint32(out[:], word)
		copy(dst, out[:])
	}
	return invalid == 0
}

// hexToBytes converts canonical hex to bytes: an even number of hex digits in either
// case, and nothing else. All digits are always examined, so an invalid position does
// not show in the timing.
func hexToBytes(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errInvalidHex
	}
	out := make([]byte, len(s)/2)
	if !decodeHexInto(out, s) {
		clear(out)
		return nil, errInvalidHex
	}
	return out, nil
}

// wipeBytes overwrites b. Go gives no guarantee about copies made by the runtime, so
// this reduces how long secrets stay in memory but cannot eliminate it.
func wipeBytes(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}
