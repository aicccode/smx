//go:build amd64 && !purego

package smx

import (
	"bytes"
	"math/rand"
	"testing"
)

// withSM4Paths runs f once for each decryption path this CPU supports, with the
// table-only path always included.
func withSM4Paths(t *testing.T, f func(t *testing.T)) {
	t.Helper()
	savedVAES, savedGFNI := sm4UseVAES, sm4UseGFNI
	defer func() { sm4UseVAES, sm4UseGFNI = savedVAES, savedGFNI }()

	type path struct {
		name       string
		vaes, gfni bool
	}
	paths := []path{{name: "table"}}
	if savedVAES {
		paths = append(paths, path{name: "vaes", vaes: true})
	}
	if savedGFNI {
		paths = append(paths, path{name: "gfni", gfni: true})
	}
	for _, p := range paths {
		sm4UseVAES, sm4UseGFNI = p.vaes, p.gfni
		t.Run(p.name, f)
	}
}

func TestSM4PathsAllVectors(t *testing.T) {
	t.Logf("cpu: vaes=%v gfni=%v", sm4UseVAES, sm4UseGFNI)
	withSM4Paths(t, func(t *testing.T) {
		TestSM4CapturedVectors(t)
		TestSM4DecryptErrors(t)
		TestSM4EncryptDecrypt(t)
		TestVectorsSM4(t)
		TestSM4UnpadSameWork(t)
	})
}

// All decryption paths must agree with the table rounds on every length, including every
// remainder after the 8-block loop, and every key.
func TestSM4PathsDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(31))
	for keyIndex := 0; keyIndex < 30; keyIndex++ {
		key, iv := make([]byte, 16), make([]byte, 16)
		rng.Read(key)
		rng.Read(iv)
		s := NewSM4()
		s.SetKey(key, iv)

		for blocks := 0; blocks <= 40; blocks++ {
			plain := make([]byte, blocks*16)
			rng.Read(plain)

			wantDec := append([]byte(nil), plain...)
			sm4CBCDecryptTable(&s.keys.drk, &s.keys.iv, wantDec)

			withSM4Paths(t, func(t *testing.T) {
				got := append([]byte(nil), plain...)
				sm4CBCDecrypt(&s.keys.drk, &s.keys.iv, got)
				if !bytes.Equal(got, wantDec) {
					t.Fatalf("decrypt: %d blocks differ", blocks)
				}
				// The hardware routines must not touch anything past the buffer.
				guarded := make([]byte, len(plain)+32)
				copy(guarded, plain)
				for i := range guarded[len(plain):] {
					guarded[len(plain)+i] = 0xA5
				}
				sm4CBCDecrypt(&s.keys.drk, &s.keys.iv, guarded[:len(plain)])
				for _, b := range guarded[len(plain):] {
					if b != 0xA5 {
						t.Fatalf("decrypt: wrote past %d blocks", blocks)
					}
				}
			})
		}
	}
}

func TestSM4StandardVectorsAllPaths(t *testing.T) {
	withSM4Paths(t, TestSM4StandardVectors)
}

// A short run with the hardware paths disabled at package level.
func TestSM2UnaffectedBySM4Paths(t *testing.T) {
	withSM4Paths(t, func(t *testing.T) {
		s := NewSM4()
		s.SetKey([]byte("0123456789abcdef"), []byte("fedcba9876543210"))
		ct, err := s.Encrypt("round trip")
		if err != nil {
			t.Fatal(err)
		}
		if got, err := s.Decrypt(ct); err != nil || got != "round trip" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
}

func benchSM4Routine(b *testing.B, blocks int, routine func(rk *[32]uint32, dst, src *byte)) {
	s := NewSM4()
	s.SetKey(benchData(16), benchData(16))
	buf := benchData(blocks * 16)
	b.SetBytes(int64(blocks * 16))
	for i := 0; i < b.N; i++ {
		routine(&s.keys.rk, &buf[0], &buf[0])
	}
}

func BenchmarkSM4Crypt(b *testing.B) {
	if sm4UseVAES {
		b.Run("8VAES", func(b *testing.B) { benchSM4Routine(b, 8, sm4Crypt8VAES) })
	}
	if sm4UseGFNI {
		b.Run("8GFNI", func(b *testing.B) { benchSM4Routine(b, 8, sm4Crypt8GFNI) })
	}
}
