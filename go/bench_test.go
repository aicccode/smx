package smx

import (
	"fmt"
	"testing"
)

// The benchmarks use only the public API so the same file also compiles against
// the pre-optimization code for before/after comparisons.

const (
	benchPrivateKey = "6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE"
	benchUserID     = "ALICE123@YAHOO.COM"
)

var (
	benchSizes = []struct {
		name string
		size int
	}{{"64B", 64}, {"1KB", 1024}, {"1MB", 1024 * 1024}}
	sm4BenchSizes = []struct {
		name string
		size int
	}{{"16B", 16}, {"1KB", 1024}, {"1MB", 1024 * 1024}}

	sinkString string
	sinkBool   bool
	sinkHash   [32]byte
	sinkPoint  ECPoint
)

func benchPublicKey() string {
	d := BigInt256FromHex(benchPrivateKey)
	return SM2GetPublicKey(&d).ToHexEncoded()
}

func benchData(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i*31 + 7)
	}
	return data
}

func BenchmarkSM3(b *testing.B) {
	for _, tc := range benchSizes {
		b.Run(tc.name, func(b *testing.B) {
			data := benchData(tc.size)
			b.SetBytes(int64(tc.size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				h := NewSM3()
				h.Update(data)
				h.Finish()
				sinkHash = h.HashBytes()
			}
		})
	}
}

func BenchmarkSM4KeySchedule(b *testing.B) {
	key, iv := benchData(16), benchData(16)
	b.ReportAllocs()
	s := NewSM4()
	for i := 0; i < b.N; i++ {
		s.SetKey(key, iv)
	}
}

func BenchmarkSM4Encrypt(b *testing.B) {
	s := NewSM4()
	s.SetKey(benchData(16), benchData(16))
	for _, tc := range sm4BenchSizes {
		b.Run(tc.name, func(b *testing.B) {
			plaintext := string(benchData(tc.size))
			b.SetBytes(int64(tc.size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkString, _ = s.Encrypt(plaintext)
			}
		})
	}
}

func BenchmarkSM4Decrypt(b *testing.B) {
	s := NewSM4()
	s.SetKey(benchData(16), benchData(16))
	for _, tc := range sm4BenchSizes {
		b.Run(tc.name, func(b *testing.B) {
			ciphertext, err := s.Encrypt(string(benchData(tc.size)))
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(tc.size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkString, _ = s.Decrypt(ciphertext)
			}
		})
	}
}

func BenchmarkSM2KeyGen(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString, _ = SM2GenKeyPair()
	}
}

func BenchmarkSM2Sign(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString, _ = SM2Sign(benchUserID, "encryption standard", benchPrivateKey)
	}
}

func BenchmarkSM2Verify(b *testing.B) {
	pub := benchPublicKey()
	sig, err := SM2Sign(benchUserID, "encryption standard", benchPrivateKey)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkBool = SM2Verify(benchUserID, sig, "encryption standard", pub)
	}
	if !sinkBool {
		b.Fatal("verify failed")
	}
}

func BenchmarkSM2Encrypt(b *testing.B) {
	pub := benchPublicKey()
	for _, size := range []int{32, 1024} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			msg := string(benchData(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkString, _ = SM2Encrypt(msg, pub)
			}
		})
	}
}

func BenchmarkSM2Decrypt(b *testing.B) {
	pub := benchPublicKey()
	for _, size := range []int{32, 1024} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			ct, err := SM2Encrypt(string(benchData(size)), pub)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sinkString, _ = SM2Decrypt(ct, benchPrivateKey)
			}
		})
	}
}

func BenchmarkSM2KeyExchange(b *testing.B) {
	idA, idB := "ALICE123@YAHOO.COM", "BILL456@YAHOO.COM"
	dA := BigInt256FromHex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE")
	ra := BigInt256FromHex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563")
	dB := BigInt256FromHex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53")
	rb := BigInt256FromHex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80")
	pA, rA := SM2GetPublicKey(&dA), SM2GetPublicKey(&ra)
	pB, rB := SM2GetPublicKey(&dB), SM2GetPublicKey(&rb)
	b.ReportAllocs()
	b.ResetTimer()
	// One full exchange: B computes Sb, A computes Sa and B checks Sa.
	for i := 0; i < b.N; i++ {
		resB := SM2GetSb(16, pA, rA, pB, &dB, rB, &rb, idA, idB)
		sb, _ := hexToBytes(resB.Sb)
		resA := SM2GetSa(16, pB, rB, pA, &dA, rA, &ra, idA, idB, sb)
		sa, _ := hexToBytes(resA.Sa)
		sinkBool = SM2CheckSa(*resB.V, resB.Za, resB.Zb, rA, rB, sa)
	}
	if !sinkBool {
		b.Fatal("key exchange failed")
	}
}

func BenchmarkPointMultiply(b *testing.B) {
	d := BigInt256FromHex(benchPrivateKey)
	g := ECPointGenerator()
	p := g.Twice()
	b.Run("Base", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sinkPoint = g.Multiply(&d)
		}
	})
	b.Run("Variable", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sinkPoint = p.Multiply(&d)
		}
	})
}
