//go:build amd64 && !purego

package smx

import (
	"crypto/subtle"
)

//go:noescape
func sm4Crypt8VAES(rk *[32]uint32, dst, src *byte)

//go:noescape
func sm4Crypt8GFNI(rk *[32]uint32, dst, src *byte)

func cpuid(leaf, subleaf uint32) (eax, ebx, ecx, edx uint32)

func xgetbv() (eax, edx uint32)

// The vector paths are selected at run time. The variables are only changed by tests.
// AES-NI alone, without VAES or GFNI, is not used: on the CPUs measured its four-lane
// routine was slower than the interleaved table rounds at every length.
var sm4UseVAES, sm4UseGFNI = sm4DetectCPU()

func sm4DetectCPU() (vaes, gfni bool) {
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
	if maxLeaf < 7 {
		return false, false
	}
	_, _, c1, _ := cpuid(1, 0)
	if c1&ecxOSXSAVE == 0 || c1&ecxAVX == 0 || c1&ecxAES == 0 {
		return false, false
	}
	if xcr0, _ := xgetbv(); xcr0&xcr0AVX != xcr0AVX {
		return false, false
	}
	_, b7, c7, _ := cpuid(7, 0)
	avx2 := b7&ebxAVX2 != 0
	return avx2 && c7&ecxVAES != 0, avx2 && c7&ecxGFNI != 0
}

// sm4VectorWorth reports whether a tail of 1 to 7 blocks is faster through one padded
// eight-lane call than through the table rounds, which handle 2 and 4 blocks
// interleaved and so are cheap there. From timings on an Intel Core i5-13500H: an
// eight-lane call costs about 150 ns with GFNI and 190 ns with VAES, the table rounds
// about 95, 100, 180, 125, 215, 225 and 260 ns for 1 to 7 blocks.
func sm4VectorWorth(blocks int) bool {
	return blocks >= 5 || (sm4UseGFNI && blocks == 3)
}

// sm4CBCDecrypt decrypts whole blocks of buf in place. CBC decryption is parallel, so
// groups of eight blocks go through the vector routine when the CPU has one; tails go
// wherever they are faster.
func sm4CBCDecrypt(drk *[32]uint32, iv *[16]byte, buf []byte) {
	if !sm4UseVAES && !sm4UseGFNI {
		sm4CBCDecryptTable(drk, iv, buf)
		return
	}
	prev := *iv
	for len(buf) >= 8*sm4BlockSize {
		sm4CBCDecrypt8(drk, &prev, buf[:8*sm4BlockSize])
		buf = buf[8*sm4BlockSize:]
	}
	if sm4VectorWorth(len(buf) / sm4BlockSize) {
		sm4CBCDecrypt8(drk, &prev, buf)
		return
	}
	sm4CBCDecryptTable(drk, &prev, buf)
}

// sm4CBCDecrypt8 decrypts buf, one to eight blocks, with one call of the eight-lane
// routine, and leaves its last ciphertext block in prev. A full group is worked on in
// place; a short one is padded with zero blocks.
func sm4CBCDecrypt8(drk *[32]uint32, prev *[16]byte, buf []byte) {
	var pad, saved [8 * sm4BlockSize]byte
	n := copy(saved[:], buf)
	work := buf
	if n < len(pad) {
		copy(pad[:], buf)
		work = pad[:]
	}
	if sm4UseGFNI {
		sm4Crypt8GFNI(drk, &work[0], &work[0])
	} else {
		sm4Crypt8VAES(drk, &work[0], &work[0])
	}
	subtle.XORBytes(work[:sm4BlockSize], work[:sm4BlockSize], prev[:])
	subtle.XORBytes(work[sm4BlockSize:n], work[sm4BlockSize:n], saved[:n-sm4BlockSize])
	copy(prev[:], saved[n-sm4BlockSize:n])
	if n < len(pad) {
		copy(buf, pad[:n])
		wipeBytes(pad[:])
	}
}
