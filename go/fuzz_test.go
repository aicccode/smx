package smx

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

const (
	fuzzPrivate = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
	fuzzPublic  = "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020" +
		"ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"
)

func FuzzBigIntHex(f *testing.F) {
	for _, s := range []string{"", "0", "1", "0x1", "0X", "abc", "zz", strings.Repeat("f", 64), strings.Repeat("f", 65), "é"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		parsed, err := BigInt256ParseHex(s)
		lenient := BigInt256FromHex(s)
		if parsed != lenient {
			t.Fatal("ParseHex and FromHex disagree")
		}
		if err != nil {
			if !parsed.IsZero() {
				t.Fatal("failure with a non-zero value")
			}
			return
		}
		digits := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
		if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
			digits = s[2:]
		}
		want, ok := new(big.Int).SetString(digits, 16)
		if !ok || limbsToBig(parsed.limbs).Cmp(want) != 0 {
			t.Fatalf("ParseHex(%q) = %x", s, limbsToBig(parsed.limbs))
		}
		if len(strings.TrimLeft(parsed.ToHex(), "0"))+64 < 64 || len(parsed.ToHexLower()) != 64 {
			t.Fatal("bad hex output")
		}
	})
}

func FuzzHexDecode(f *testing.F) {
	for _, s := range []string{"", "00", "0", "zz", "aB", "0x00", "\xff\xff", "0123456789abcdefABCDEF"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, gotErr := hexToBytes(s)
		want, wantErr := hex.DecodeString(s)
		if (gotErr == nil) != (wantErr == nil) {
			t.Fatalf("hexToBytes(%q): %v vs %v", s, gotErr, wantErr)
		}
		if gotErr == nil && string(got) != string(want) {
			t.Fatalf("hexToBytes(%q) = %x", s, got)
		}
		if bytesToHex([]byte(s)) != hex.EncodeToString([]byte(s)) {
			t.Fatalf("bytesToHex(%q)", s)
		}
	})
}

func FuzzPointDecode(f *testing.F) {
	raw, _ := hex.DecodeString(fuzzPublic)
	f.Add(raw)
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{4})
	f.Add(make([]byte, 65))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := ECPointFromEncoded(data)
		q := SM2DecodePoint(hex.EncodeToString(data))
		if !p.Equal(q) {
			t.Fatal("decoders disagree")
		}
		r, err := SM2ParsePublicKey(hex.EncodeToString(data))
		if (err == nil) == p.Infinity || !r.Equal(p) {
			t.Fatal("SM2ParsePublicKey disagrees")
		}
		if !p.Infinity {
			if !p.IsOnCurve() || string(p.ToEncoded()) != string(data) {
				t.Fatal("accepted a non-canonical point")
			}
		}
	})
}

func FuzzPublicKeyString(f *testing.F) {
	for _, s := range []string{"", "00", "04", fuzzPublic, fuzzPublic + "00", fuzzPublic[:129], "é"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, parseErr := SM2ParsePublicKey(s)
		if p := ECPointFromHexEncoded(s); p.Infinity != (parseErr != nil) {
			t.Fatal("decoders disagree")
		}
		ct, err := SM2Encrypt("message", s)
		if (err == nil) != (parseErr == nil) {
			t.Fatalf("SM2Encrypt(%q): %v", s, err)
		}
		if err == nil && len(ct) != 130+64+14 {
			t.Fatalf("ciphertext length %d", len(ct))
		}
		if SM2Verify("id", strings.Repeat("1", 64)+"h"+strings.Repeat("1", 64), "m", s) {
			t.Fatal("verified an arbitrary signature")
		}
	})
}

func FuzzSM2Verify(f *testing.F) {
	sig := "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3" +
		"h" + "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa"
	f.Add("1234567812345678", sig, "message digest", fuzzPublic)
	f.Add("", "", "", "")
	f.Add("id", "h", "m", "04")
	f.Fuzz(func(t *testing.T, id, signature, msg, pub string) {
		if SM2Verify(id, signature, msg, pub) && (id != "1234567812345678" || msg != "message digest") {
			// A forgery found by the fuzzer would be a total break.
			t.Fatalf("verified id=%q sig=%q msg=%q pub=%q", id, signature, msg, pub)
		}
	})
}

func FuzzSM2Decrypt(f *testing.F) {
	ct, err := SM2Encrypt("seed plaintext", fuzzPublic)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(ct, fuzzPrivate)
	f.Add(ct+"00", fuzzPrivate)
	f.Add(ct, "")
	f.Add("", "")
	f.Add(ct[:194], fuzzPrivate)
	f.Fuzz(func(t *testing.T, ciphertext, privateKey string) {
		got, err := SM2Decrypt(ciphertext, privateKey)
		if err != nil && got != "" {
			t.Fatal("returned plaintext with an error")
		}
		if err == nil && (privateKey != fuzzPrivate && !strings.EqualFold(privateKey, fuzzPrivate)) {
			// Only a ciphertext made for this key can pass the C3 check.
			if _, parseErr := parsePrivateKey(privateKey); parseErr != nil {
				t.Fatalf("decrypted with invalid key %q", privateKey)
			}
		}
	})
}

func FuzzSM2Sign(f *testing.F) {
	f.Add("id", "message", fuzzPrivate)
	f.Add("", "", "")
	f.Add(strings.Repeat("a", 8192), "m", fuzzPrivate)
	f.Add("id", "m", "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54122")
	f.Fuzz(func(t *testing.T, id, msg, key string) {
		sig, err := SM2Sign(id, msg, key)
		if err != nil {
			if sig != "" {
				t.Fatal("signature with an error")
			}
			return
		}
		d, parseErr := parsePrivateKey(key)
		if parseErr != nil {
			t.Fatalf("signed with invalid key %q", key)
		}
		if !SM2Verify(id, sig, msg, SM2GetPublicKey(&d).ToHexEncoded()) {
			t.Fatalf("own signature rejected: id=%q msg=%q key=%q", id, msg, key)
		}
	})
}

func FuzzSM2RoundTrip(f *testing.F) {
	f.Add("hello")
	f.Add("\xff\x00invalid utf8")
	f.Add(strings.Repeat("x", 1000))
	f.Fuzz(func(t *testing.T, msg string) {
		ct, err := SM2Encrypt(msg, fuzzPublic)
		if msg == "" {
			if err == nil {
				t.Fatal("empty plaintext accepted")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		got, err := SM2Decrypt(ct, fuzzPrivate)
		if err != nil || got != msg {
			t.Fatalf("round trip: %v", err)
		}
	})
}

func FuzzSM4(f *testing.F) {
	key := []byte("0123456789abcdef")
	f.Add(key, key, "plaintext", "")
	f.Add(key, key, "", "00")
	f.Add([]byte{}, []byte{}, "", "")
	f.Add(key[:15], key, "x", strings.Repeat("00", 16))
	f.Add(key, key, strings.Repeat("y", 300), "zz")
	f.Fuzz(func(t *testing.T, k, iv []byte, plain, ciphertext string) {
		s := NewSM4()
		err := s.TrySetKey(k, iv)
		if (err == nil) != (len(k) == 16 && len(iv) == 16) {
			t.Fatalf("TrySetKey(%d, %d): %v", len(k), len(iv), err)
		}
		ct, encErr := s.Encrypt(plain)
		_, decErr := s.Decrypt(ciphertext)
		if err != nil {
			if encErr != errSM4KeyNotSet || decErr != errSM4KeyNotSet {
				t.Fatal("cipher ran with no key")
			}
			return
		}
		if decErr != nil && decErr != errSM4Decrypt {
			t.Fatalf("distinguishable error: %v", decErr)
		}
		got, err := s.Decrypt(ct)
		if encErr != nil || err != nil || got != plain {
			t.Fatalf("round trip: %v %v", encErr, err)
		}
		// All paths agree.
		raw, _ := hex.DecodeString(ct)
		same := append([]byte(nil), raw...)
		sm4CBCDecryptGeneric(&s.drk, &s.iv, same)
		if string(same[:len(plain)]) != plain {
			t.Fatal("portable decryption differs")
		}
		back := append([]byte(nil), same...)
		sm4CBCEncryptGeneric(&s.rk, &s.iv, back)
		if string(back) != string(raw) {
			t.Fatal("portable encryption differs")
		}
	})
}

func FuzzPKCS7(f *testing.F) {
	f.Add(make([]byte, 16))
	f.Add([]byte("0123456789abcde\x01"))
	f.Add([]byte(strings.Repeat("\x10", 16)))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 16 {
			return
		}
		got, ok := pkcs7PadLen(data)
		p := int(data[len(data)-1])
		want := p >= 1 && p <= 16
		if want {
			for _, c := range data[len(data)-p:] {
				want = want && int(c) == p
			}
		}
		if ok != want || (ok && got != p) {
			t.Fatalf("pkcs7PadLen(%x) = %d, %v", data, got, ok)
		}
	})
}

func FuzzSM3Chunks(f *testing.F) {
	f.Add([]byte("abc"), uint16(1))
	f.Add(make([]byte, 200), uint16(64))
	f.Add(make([]byte, 56), uint16(55))
	f.Fuzz(func(t *testing.T, data []byte, split uint16) {
		whole := NewSM3()
		whole.Update(data)
		whole.Finish()
		var chunked SM3 // the zero value
		size := int(split)%97 + 1
		for rest := data; len(rest) > 0; {
			n := size
			if n > len(rest) {
				n = len(rest)
			}
			if n == 1 {
				chunked.UpdateByte(rest[0])
			} else {
				chunked.Update(rest[:n])
			}
			rest = rest[n:]
		}
		chunked.Finish()
		if whole.HashHexUpper() != chunked.HashHexUpper() {
			t.Fatal("chunking changed the digest")
		}
	})
}

func FuzzKeyExchange(f *testing.F) {
	f.Add(16, fuzzPublic, fuzzPublic, fuzzPrivate, fuzzPrivate, "a", "b", []byte{1})
	f.Add(0, "", "", "", "", "", "", []byte{})
	f.Add(-1, "00", "04", "zz", "0", "a", "b", make([]byte, 32))
	f.Add(1<<21, fuzzPublic, fuzzPublic, fuzzPrivate, fuzzPrivate, "a", "b", make([]byte, 32))
	f.Fuzz(func(t *testing.T, n int, pub1, pub2, d1, d2, idA, idB string, sb []byte) {
		if n > 4096 && n <= sm2MaxKeyExchangeBytes {
			n = 4096
		}
		p1, p2 := SM2DecodePoint(pub1), SM2DecodePoint(pub2)
		k1, k2 := BigInt256FromHex(d1), BigInt256FromHex(d2)
		b := SM2GetSb(n, p1, p2, p1, &k1, p2, &k2, idA, idB)
		if b.Success {
			if p1.Infinity || p2.Infinity || n < 1 || !privateKeyInRange(&k1.limbs) || !privateKeyInRange(&k2.limbs) {
				t.Fatal("exchange succeeded on invalid input")
			}
			if len(b.Kb) != 2*n || len(b.Sb) != 64 || b.V == nil || b.V.Infinity {
				t.Fatal("malformed result")
			}
		}
		a := SM2GetSa(n, p1, p2, p1, &k1, p2, &k2, idA, idB, sb)
		if a.Success && len(sb) != 32 {
			t.Fatal("accepted a bad Sb length")
		}
		if SM2CheckSa(p1, sb, sb, p1, p2, sb) && len(sb) != 32 {
			t.Fatal("accepted a bad Sa length")
		}
	})
}

func FuzzBigIntArithmetic(f *testing.F) {
	full := make([]byte, 32)
	for i := range full {
		full[i] = 0xFF
	}
	f.Add(full, full, full, 3, []byte{2})
	f.Add([]byte{}, []byte{}, []byte{}, -1, []byte{})
	f.Add([]byte{1}, []byte{2}, []byte{7}, 300, []byte{5})
	f.Add(full, full, limbsToBytes(curveP), 0, full)
	f.Add(full, full, limbsToBytes(curveN), 0, full)
	f.Fuzz(func(t *testing.T, a, b, m []byte, i int, e []byte) {
		if len(a) > 32 || len(b) > 32 || len(m) > 32 || len(e) > 32 {
			if !BigInt256FromBEBytes(a).IsZero() && len(a) > 32 {
				t.Fatal("oversized input not rejected")
			}
			return
		}
		x, y, mod, exp := BigInt256FromBEBytes(a), BigInt256FromBEBytes(b), BigInt256FromBEBytes(m), BigInt256FromBEBytes(e)
		bx, by, bm, be := new(big.Int).SetBytes(a), new(big.Int).SetBytes(b), new(big.Int).SetBytes(m), new(big.Int).SetBytes(e)

		_ = x.GetBit(i)
		_ = x.ModAdd(&y, &mod)
		_ = x.ModSub(&y, &mod)
		if got := x.Compare(&y); got != bx.Cmp(by) {
			t.Fatal("Compare")
		}
		if bm.Sign() == 0 {
			if !x.ModMul(&y, &mod).IsZero() || !x.ModPow(&exp, &mod).IsZero() {
				t.Fatal("zero modulus")
			}
			return
		}
		want := new(big.Int).Mul(bx, by)
		want.Mod(want, bm)
		if got := x.ModMul(&y, &mod); limbsToBig(got.limbs).Cmp(want) != 0 {
			t.Fatalf("ModMul(%x, %x, %x)", bx, by, bm)
		}
		if be.Sign() != 0 && len(e) <= 4 {
			want := new(big.Int).Exp(bx, be, bm)
			if got := x.ModPow(&exp, &mod); limbsToBig(got.limbs).Cmp(want) != 0 {
				t.Fatalf("ModPow(%x, %x, %x)", bx, be, bm)
			}
		}
		_ = x.ModInverse(&mod)
		fx, fy := NewFpElement(x), NewFpElement(y)
		_ = fx.Div(fy)
		p := NewECPoint(fx, fy)
		if q := p.Multiply(&y); !p.IsOnCurve() && !q.Infinity {
			t.Fatal("multiplied an off-curve point")
		}
		_ = p.Add(p)
		_ = p.Twice()
		_ = p.Negate()
		_ = p.Subtract(p)
		_ = p.ToHexEncoded()
	})
}
