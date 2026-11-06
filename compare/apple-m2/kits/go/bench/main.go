// Command bench times the SMX Go library through its public API. The same source builds
// against the baseline (3397c6d) and the current tree; see NOTES.md.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"time"

	"smx"
)

const (
	userID      = "1234567812345678"
	warmup      = 500 * time.Millisecond
	samples     = 7
	minSampleNs = int64(200 * time.Millisecond)
)

var sink any

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		die("rand: %v", err)
	}
	return b
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "bench: "+format+"\n", args...)
	os.Exit(1)
}

// measure warms up, then takes 7 samples of at least 200 ms and prints the median and
// minimum in microseconds per operation.
func measure(name string, op func()) {
	deadline := time.Now().Add(warmup)
	n := 1
	for time.Now().Before(deadline) {
		for i := 0; i < n; i++ {
			op()
		}
		n *= 2
	}
	// Calibrate a batch that takes about a tenth of a sample.
	batch := 1
	for {
		start := time.Now()
		for i := 0; i < batch; i++ {
			op()
		}
		if time.Since(start).Nanoseconds() >= minSampleNs/10 {
			break
		}
		batch *= 2
	}
	results := make([]float64, 0, samples)
	for s := 0; s < samples; s++ {
		count := 0
		start := time.Now()
		var elapsed int64
		for elapsed < minSampleNs {
			for i := 0; i < batch; i++ {
				op()
			}
			count += batch
			elapsed = time.Since(start).Nanoseconds()
		}
		results = append(results, float64(elapsed)/float64(count)/1000)
	}
	sort.Float64s(results)
	fmt.Printf("%s\t%.3f\t%.3f\n", name, results[samples/2], results[0])
}

func sm3(data []byte) [32]byte {
	h := smx.NewSM3()
	h.Update(data)
	h.Finish()
	return h.HashBytes()
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		die("hex: %v", err)
	}
	return b
}

// keyExchange runs one complete exchange with fresh ephemeral keys and returns whether
// both sides agree and the confirmations check.
func keyExchange(dA, pA, dB, pB string) bool {
	raHex, rAHex := smx.SM2GenKeyPair()
	rbHex, rBHex := smx.SM2GenKeyPair()
	da, db := smx.BigInt256FromHex(dA), smx.BigInt256FromHex(dB)
	ra, rb := smx.BigInt256FromHex(raHex), smx.BigInt256FromHex(rbHex)
	pointA, pointB := smx.SM2DecodePoint(pA), smx.SM2DecodePoint(pB)
	rA, rB := smx.SM2DecodePoint(rAHex), smx.SM2DecodePoint(rBHex)

	resB := smx.SM2GetSb(16, pointA, rA, pointB, &db, rB, &rb, userID, userID)
	if !resB.Success {
		return false
	}
	resA := smx.SM2GetSa(16, pointB, rB, pointA, &da, rA, &ra, userID, userID, mustHex(resB.Sb))
	if !resA.Success || resA.Ka != resB.Kb || len(resA.Ka) != 32 {
		return false
	}
	return smx.SM2CheckSa(*resB.V, resB.Za, resB.Zb, rA, rB, mustHex(resA.Sa))
}

func main() {
	// SM3: known answer, outside timing.
	if got := hex.EncodeToString(func() []byte { d := sm3([]byte("abc")); return d[:] }()); got !=
		"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" {
		die("SM3 known answer failed: %s", got)
	}
	for _, size := range []struct {
		name string
		n    int
	}{{"64B", 64}, {"1KB", 1024}, {"1MB", 1 << 20}} {
		data := randBytes(size.n)
		measure("sm3/"+size.name, func() { sink = sm3(data) })
	}

	key, iv := randBytes(16), randBytes(16)
	cipher := smx.NewSM4()
	measure("sm4/key_schedule", func() { cipher.SetKey(key, iv) })
	cipher.SetKey(key, iv)
	type sm4Case struct {
		name       string
		plaintext  string
		ciphertext string
	}
	var cases []sm4Case
	for _, size := range []struct {
		name string
		n    int
	}{{"16B", 16}, {"1KB", 1024}, {"1MB", 1 << 20}} {
		plain := string(randBytes(size.n))
		ct, err := cipher.Encrypt(plain)
		if err != nil {
			die("SM4 encrypt: %v", err)
		}
		if len(ct) != 2*(size.n+16) {
			die("SM4 ciphertext length %d", len(ct))
		}
		if back, err := cipher.Decrypt(ct); err != nil || back != plain {
			die("SM4 round trip failed: %v", err)
		}
		cases = append(cases, sm4Case{size.name, plain, ct})
	}
	for _, c := range cases {
		c := c
		measure("sm4/cbc_encrypt/"+c.name, func() {
			out, err := cipher.Encrypt(c.plaintext)
			if err != nil {
				die("SM4 encrypt: %v", err)
			}
			sink = out
		})
	}
	for _, c := range cases {
		c := c
		measure("sm4/cbc_decrypt/"+c.name, func() {
			out, err := cipher.Decrypt(c.ciphertext)
			if err != nil {
				die("SM4 decrypt: %v", err)
			}
			sink = out
		})
	}

	measure("sm2/keygen", func() {
		priv, pub := smx.SM2GenKeyPair()
		sink = priv + pub
	})
	priv, pub := smx.SM2GenKeyPair()
	if len(priv) != 64 || len(pub) != 130 {
		die("SM2 key generation failed")
	}
	message := string(randBytes(32))
	sig, err := smx.SM2Sign(userID, message, priv)
	if err != nil || !smx.SM2Verify(userID, sig, message, pub) {
		die("SM2 signature does not verify: %v", err)
	}
	if smx.SM2Verify(userID, sig, message+"x", pub) {
		die("SM2 verify accepted a wrong message")
	}
	measure("sm2/sign", func() {
		s, err := smx.SM2Sign(userID, message, priv)
		if err != nil {
			die("SM2 sign: %v", err)
		}
		sink = s
	})
	measure("sm2/verify", func() {
		if !smx.SM2Verify(userID, sig, message, pub) {
			die("SM2 verify failed")
		}
	})

	plain := string(randBytes(32))
	ct, err := smx.SM2Encrypt(plain, pub)
	if err != nil {
		die("SM2 encrypt: %v", err)
	}
	if back, err := smx.SM2Decrypt(ct, priv); err != nil || back != plain {
		die("SM2 decrypt round trip failed: %v", err)
	}
	measure("sm2/encrypt/32B", func() {
		c, err := smx.SM2Encrypt(plain, pub)
		if err != nil {
			die("SM2 encrypt: %v", err)
		}
		sink = c
	})
	measure("sm2/decrypt/32B", func() {
		p, err := smx.SM2Decrypt(ct, priv)
		if err != nil {
			die("SM2 decrypt: %v", err)
		}
		sink = p
	})

	privB, pubB := smx.SM2GenKeyPair()
	if !keyExchange(priv, pub, privB, pubB) {
		die("SM2 key exchange failed")
	}
	measure("sm2/key_exchange", func() {
		if !keyExchange(priv, pub, privB, pubB) {
			die("SM2 key exchange failed")
		}
	})
}
