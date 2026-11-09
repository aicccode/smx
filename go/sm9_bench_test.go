package smx

import (
	"fmt"
	"testing"
)

// SM9 benchmarks through the public API, mirroring the SM2 ones.

type sm9BenchKeys struct {
	signPub, signUser, encPub, encUser, exA, exB string
}

const (
	sm9BenchSignMaster = "1f2e3d4c5b6a79880102030405060708090a0b0c0d0e0f101112131415161718"
	sm9BenchEncMaster  = "2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70819"
	sm9BenchID         = "alice@example.com"
	sm9BenchPeer       = "bob@example.com"
)

func sm9Bench(b *testing.B) sm9BenchKeys {
	b.Helper()
	var k sm9BenchKeys
	var err error
	must := func(s string, e error) string {
		if e != nil {
			b.Fatal(e)
		}
		return s
	}
	k.signPub = must(SM9SignMasterPublicKey(sm9BenchSignMaster))
	k.signUser = must(SM9GenerateSignUserKey(sm9BenchSignMaster, sm9BenchID, SM9HIDSign))
	k.encPub = must(SM9EncryptMasterPublicKey(sm9BenchEncMaster))
	k.encUser = must(SM9GenerateEncryptUserKey(sm9BenchEncMaster, sm9BenchID, SM9HIDEncrypt))
	k.exA = must(SM9GenerateEncryptUserKey(sm9BenchEncMaster, sm9BenchID, SM9HIDExchange))
	k.exB, err = SM9GenerateEncryptUserKey(sm9BenchEncMaster, sm9BenchPeer, SM9HIDExchange)
	must("", err)
	return k
}

func BenchmarkSM9Pairing(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		g := sm9Pair(&sm9P1, &sm9P2)
		sinkBool = g.c0.b0.a0[0] == 0
	}
}

func BenchmarkSM9SignUserKey(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString, _ = SM9GenerateSignUserKey(sm9BenchSignMaster, sm9BenchID, SM9HIDSign)
	}
}

func BenchmarkSM9EncryptUserKey(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString, _ = SM9GenerateEncryptUserKey(sm9BenchEncMaster, sm9BenchID, SM9HIDEncrypt)
	}
}

func BenchmarkSM9Sign(b *testing.B) {
	k := sm9Bench(b)
	msg := []byte("encryption standard")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkString, _ = SM9Sign(msg, k.signUser, k.signPub)
	}
}

func BenchmarkSM9Verify(b *testing.B) {
	k := sm9Bench(b)
	msg := []byte("encryption standard")
	sig, err := SM9Sign(msg, k.signUser, k.signPub)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkBool = SM9Verify(msg, sig, sm9BenchID, k.signPub, SM9HIDSign)
	}
	if !sinkBool {
		b.Fatal("verify failed")
	}
}

func BenchmarkSM9Encrypt(b *testing.B) {
	k := sm9Bench(b)
	for _, size := range []int{32, 1024} {
		for _, mode := range []SM9EncryptMode{SM9ModeStream, SM9ModeSM4} {
			b.Run(fmt.Sprintf("%dB/mode%d", size, mode), func(b *testing.B) {
				msg := benchData(size)
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					sinkString, _ = SM9Encrypt(msg, sm9BenchID, k.encPub, SM9HIDEncrypt, mode)
				}
			})
		}
	}
}

func BenchmarkSM9Decrypt(b *testing.B) {
	k := sm9Bench(b)
	for _, size := range []int{32, 1024} {
		for _, mode := range []SM9EncryptMode{SM9ModeStream, SM9ModeSM4} {
			b.Run(fmt.Sprintf("%dB/mode%d", size, mode), func(b *testing.B) {
				ct, err := SM9Encrypt(benchData(size), sm9BenchID, k.encPub, SM9HIDEncrypt, mode)
				if err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					pt, _ := SM9Decrypt(ct, sm9BenchID, k.encUser, mode)
					sinkBool = len(pt) == size
				}
			})
		}
	}
}

func BenchmarkSM9Encapsulate(b *testing.B) {
	k := sm9Bench(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkString, _, _ = SM9Encapsulate(sm9BenchID, k.encPub, 32, SM9HIDEncrypt)
	}
}

func BenchmarkSM9Decapsulate(b *testing.B) {
	k := sm9Bench(b)
	_, ct, err := SM9Encapsulate(sm9BenchID, k.encPub, 32, SM9HIDEncrypt)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkString, _ = SM9Decapsulate(ct, sm9BenchID, k.encUser, 32)
	}
}

// BenchmarkSM9KeyExchange runs one full exchange: both inits, respond, confirm, check.
func BenchmarkSM9KeyExchange(b *testing.B) {
	k := sm9Bench(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rA, RA, _ := SM9ExchangeInit(sm9BenchPeer, k.encPub, SM9HIDExchange)
		rB, RB, _ := SM9ExchangeInit(sm9BenchID, k.encPub, SM9HIDExchange)
		resB := SM9ExchangeRespond(16, sm9BenchID, sm9BenchPeer, k.encPub, k.exB, rB, RB, RA)
		resA := SM9ExchangeConfirm(16, sm9BenchID, sm9BenchPeer, k.encPub, k.exA, rA, RA, RB, resB.SB)
		sinkBool = SM9ExchangeCheck(resB.S2, resA.SA)
	}
	if !sinkBool {
		b.Fatal("key exchange failed")
	}
}

func BenchmarkSM9Internals(b *testing.B) {
	k := [4]uint64{0x1234567890abcdef, 0xfedcba0987654321, 0x1111111122222222, 0x3333333344444444}
	g := sm9Pair(&sm9P1, &sm9P2)
	enc := sm9P2.bytes()
	b.Run("G1Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, sinkBool = sm9G1Mul(&sm9P1, &k)
		}
	})
	b.Run("G2Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, sinkBool = sm9G2Mul(&sm9P2, &k)
		}
	})
	b.Run("G2Decode", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, sinkBool = sm9G2FromBytes(enc[:])
		}
	})
	b.Run("GTExp", func(b *testing.B) {
		var z sm9Fp12
		for i := 0; i < b.N; i++ {
			sm9GTExp(&z, &g, &k)
		}
	})
	b.Run("MillerLoop", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			g = sm9MillerLoop(&sm9P1, &sm9P2)
		}
	})
	b.Run("FinalExp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			g = sm9FinalExp(&g)
		}
	})
}
