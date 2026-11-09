package smx

import (
	"bytes"
	"testing"
)

// Standard vectors from GB/T 38635.5, used as fuzz seeds.
const (
	sm9FuzzSignPub = "049f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c40829dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea5e3269850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0ef1c2541e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05fb4e3216d"
	sm9FuzzSig     = "823c4b21e4bd2dfe1ed92c606653e996668563152fc33f55d7bfbb9bd9705adb0473bf96923ce58b6ad0e13e9643a406d8eb98417c50ef1b29cef9adb48b6d598c856712f1c2e0968ab7769f42a99586aed139d5b8b3e15891827cc2aced9baa05"
	sm9FuzzEncUser = "0494736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf41683115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b1587aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55f27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1"
	sm9FuzzCT      = "042445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0ba672387bcd6de5016a158a52bb2e7fc429197bcab70b25afee37a2b9db9f3671b5f5b0e951489682f3e64e1378cdd5da9513b1c"
)

// FuzzSM9Verify: no input panics, and only the genuine signature verifies.
func FuzzSM9Verify(f *testing.F) {
	f.Add([]byte("Chinese IBS standard"), sm9FuzzSig, "Alice", byte(1))
	f.Add([]byte(""), sm9FuzzSig[:100], "", byte(0))
	f.Add([]byte("x"), "", "Alice", byte(1))
	f.Fuzz(func(t *testing.T, msg []byte, sig, id string, hid byte) {
		ok := SM9Verify(msg, sig, id, sm9FuzzSignPub, hid)
		genuine := string(msg) == "Chinese IBS standard" && sig == sm9FuzzSig && id == "Alice" && hid == 1
		if ok != genuine {
			t.Fatalf("Verify = %t for %q %q %q %d", ok, msg, sig, id, hid)
		}
	})
}

// FuzzSM9Decrypt: no ciphertext panics; anything other than the genuine one fails with
// the single decryption error.
func FuzzSM9Decrypt(f *testing.F) {
	f.Add(sm9FuzzCT, 0)
	f.Add(sm9FuzzCT[:200], 1)
	f.Add("", 0)
	f.Fuzz(func(t *testing.T, ct string, mode int) {
		m := SM9EncryptMode(mode & 1)
		pt, err := SM9Decrypt(ct, "Bob", sm9FuzzEncUser, m)
		if ct == sm9FuzzCT && m == SM9ModeStream {
			if err != nil || !bytes.Equal(pt, []byte("Chinese IBE standard")) {
				t.Fatal("genuine ciphertext rejected")
			}
			return
		}
		if err == nil {
			t.Fatalf("forged ciphertext accepted: %q", ct)
		}
		if err != errSM9Decrypt {
			t.Fatalf("unexpected error %v", err)
		}
	})
}

// FuzzSM9Points: the decoders never panic and accept only canonical, valid encodings that
// re-encode to the same bytes.
func FuzzSM9Points(f *testing.F) {
	g1, g2 := sm9P1.bytes(), sm9P2.bytes()
	f.Add(g1[:])
	f.Add(g2[:])
	f.Add([]byte{4})
	f.Fuzz(func(t *testing.T, b []byte) {
		if p, ok := sm9G1FromBytes(b); ok {
			if enc := p.bytes(); !bytes.Equal(enc[:], b) || !p.onCurve() {
				t.Fatal("G1 round trip")
			}
		}
		if p, ok := sm9G2FromBytes(b); ok {
			if enc := p.bytes(); !bytes.Equal(enc[:], b) || !p.inSubgroup() {
				t.Fatal("G2 round trip")
			}
		}
		if len(b) == 64 {
			s := string(b)
			if k, ok := sm9ParseScalar(s); ok && !sm9NInRange(&k) {
				t.Fatal("scalar out of range accepted")
			}
		}
	})
}
