//go:build amd64 && !purego

package smx

import (
	"crypto/subtle"
	"encoding/binary"
)

//go:noescape
func sm4Crypt4AVX(rk *[32]uint32, dst, src *byte)

//go:noescape
func sm4Crypt8VAES(rk *[32]uint32, dst, src *byte)

//go:noescape
func sm4Crypt4GFNI(rk *[32]uint32, dst, src *byte)

//go:noescape
func sm4Crypt8GFNI(rk *[32]uint32, dst, src *byte)

func cpuid(leaf, subleaf uint32) (eax, ebx, ecx, edx uint32)

func xgetbv() (eax, edx uint32)

// The hardware paths are selected at run time. The variables are only changed by tests.
var sm4UseAVX, sm4UseVAES, sm4UseGFNI = sm4DetectCPU()

// sm4Crypt4 runs four blocks through the fastest available routine.
func sm4Crypt4(rk *[32]uint32, dst, src *byte) {
	if sm4UseGFNI {
		sm4Crypt4GFNI(rk, dst, src)
	} else {
		sm4Crypt4AVX(rk, dst, src)
	}
}

func sm4DetectCPU() (avxAES, vaes, gfni bool) {
	const (
		ecxAES     = 1 << 25
		ecxOSXSAVE = 1 << 27
		ecxAVX     = 1 << 28
		ebxAVX2    = 1 << 5
		ecxVAES    = 1 << 9
		ecxGFNI    = 1 << 8
		xcr0AVX    = 0x6 // the OS saves XMM and YMM state
	)
	maxLeaf, _, _, _ := cpuid(0, 0)
	if maxLeaf < 1 {
		return false, false, false
	}
	_, _, c1, _ := cpuid(1, 0)
	if c1&ecxOSXSAVE == 0 || c1&ecxAVX == 0 || c1&ecxAES == 0 {
		return false, false, false
	}
	if xcr0, _ := xgetbv(); xcr0&xcr0AVX != xcr0AVX {
		return false, false, false
	}
	if maxLeaf < 7 {
		return true, false, false
	}
	_, b7, c7, _ := cpuid(7, 0)
	avx2 := b7&ebxAVX2 != 0
	return true, avx2 && c7&ecxVAES != 0, avx2 && c7&ecxGFNI != 0
}

// sm4CBCEncrypt encrypts whole blocks of buf in place.
func sm4CBCEncrypt(rk *[32]uint32, iv *[16]byte, buf []byte) {
	if !sm4UseAVX {
		sm4CBCEncryptGeneric(rk, iv, buf)
		return
	}
	// CBC encryption is serial, so only the first lane of the four carries data.
	var lanes [64]byte
	chain0 := binary.LittleEndian.Uint64(iv[0:])
	chain1 := binary.LittleEndian.Uint64(iv[8:])
	for ; len(buf) >= 16; buf = buf[16:] {
		binary.LittleEndian.PutUint64(lanes[0:], chain0^binary.LittleEndian.Uint64(buf[0:]))
		binary.LittleEndian.PutUint64(lanes[8:], chain1^binary.LittleEndian.Uint64(buf[8:]))
		sm4Crypt4(rk, &lanes[0], &lanes[0])
		chain0 = binary.LittleEndian.Uint64(lanes[0:])
		chain1 = binary.LittleEndian.Uint64(lanes[8:])
		binary.LittleEndian.PutUint64(buf[0:], chain0)
		binary.LittleEndian.PutUint64(buf[8:], chain1)
	}
}

// sm4CBCDecrypt decrypts whole blocks of buf in place, in parallel where possible.
func sm4CBCDecrypt(drk *[32]uint32, iv *[16]byte, buf []byte) {
	if !sm4UseAVX {
		sm4CBCDecryptGeneric(drk, iv, buf)
		return
	}
	prev := *iv
	if sm4UseVAES || sm4UseGFNI {
		buf = sm4CBCDecryptWide(drk, &prev, buf)
	}
	var saved [64]byte
	for len(buf) >= 64 {
		copy(saved[:], buf[:64])
		sm4Crypt4(drk, &buf[0], &buf[0])
		subtle.XORBytes(buf[:16], buf[:16], prev[:])
		subtle.XORBytes(buf[16:64], buf[16:64], saved[:48])
		copy(prev[:], saved[48:])
		buf = buf[64:]
	}
	if len(buf) > 0 {
		// One to three blocks are left; the unused lanes carry zeros.
		var lanes [64]byte
		copy(lanes[:], buf)
		copy(saved[:], buf)
		sm4Crypt4(drk, &lanes[0], &lanes[0])
		subtle.XORBytes(lanes[:16], lanes[:16], prev[:])
		subtle.XORBytes(lanes[16:48], lanes[16:48], saved[:32])
		copy(buf, lanes[:])
	}
}

// sm4CBCDecryptWide handles eight blocks at a time and returns the remaining input.
func sm4CBCDecryptWide(drk *[32]uint32, prev *[16]byte, buf []byte) []byte {
	var saved [128]byte
	for len(buf) >= 128 {
		copy(saved[:], buf[:128])
		if sm4UseGFNI {
			sm4Crypt8GFNI(drk, &buf[0], &buf[0])
		} else {
			sm4Crypt8VAES(drk, &buf[0], &buf[0])
		}
		subtle.XORBytes(buf[:16], buf[:16], prev[:])
		subtle.XORBytes(buf[16:128], buf[16:128], saved[:112])
		copy(prev[:], saved[112:])
		buf = buf[128:]
	}
	return buf
}
