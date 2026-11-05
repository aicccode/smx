package smx

import (
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"
)

func TestHexEncodeDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(21))
	for n := 0; n < 200; n++ {
		data := make([]byte, n)
		rng.Read(data)
		want := hex.EncodeToString(data)
		if got := bytesToHex(data); got != want {
			t.Fatalf("bytesToHex(%x) = %s", data, got)
		}
		upper := make([]byte, 2*n)
		encodeHexTo(upper, data, 0x07)
		if string(upper) != strings.ToUpper(want) {
			t.Fatalf("upper hex of %x = %s", data, upper)
		}
		// Encoding in place from the upper half, as SM4 and SM2 do.
		buf := make([]byte, 2*n)
		copy(buf[n:], data)
		encodeHexTo(buf, buf[n:], 0x27)
		if string(buf) != want {
			t.Fatalf("in-place hex of %x = %s", data, buf)
		}
	}
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	if got := bytesToHex(all); got != hex.EncodeToString(all) {
		t.Fatalf("all bytes: %s", got)
	}
}

// hexInputs mixes valid hex with the kinds of malformed input lenient parsers meet.
func hexInputs(rng *rand.Rand) []string {
	inputs := []string{"", "0", "00", "0x", "0X", "0x0", "0xab", "0Xab", "0x0xab", "x", "zz", "a", "abc", "ab cd", "gg00",
		"00zz", "0zz", strings.Repeat("f", 63), strings.Repeat("f", 64), strings.Repeat("f", 65), strings.Repeat("F", 64),
		strings.Repeat("a", 130), strings.Repeat("a", 131), "0x" + strings.Repeat("a", 62), "0x" + strings.Repeat("a", 64),
		strings.Repeat("0", 63) + "g", "g" + strings.Repeat("0", 63), strings.Repeat("0", 30) + "zz" + strings.Repeat("0", 32),
		"日本語", strings.Repeat("0", 62) + "\xff\xff"}
	const alphabet = "0123456789abcdefABCDEF"
	const junk = "0123456789abcdefABCDEFgxX \xff"
	for i := 0; i < 2000; i++ {
		n := rng.Intn(140)
		b := make([]byte, n)
		set := alphabet
		if i%2 == 0 {
			set = junk
		}
		for j := range b {
			b[j] = set[rng.Intn(len(set))]
		}
		inputs = append(inputs, string(b))
	}
	return inputs
}

func TestHexToBytesDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(22))
	for _, s := range hexInputs(rng) {
		got, gotErr := hexToBytes(s)
		want, wantErr := hex.DecodeString(s)
		if wantErr == nil && s != strings.ToLower(s) {
			wantErr = errInvalidHex // uppercase is not canonical
		}
		if (gotErr == nil) != (wantErr == nil) {
			t.Fatalf("hexToBytes(%q) error = %v, want %v", s, gotErr, wantErr)
		}
		if gotErr == nil && string(got) != string(want) {
			t.Fatalf("hexToBytes(%q) = %x, want %x", s, got, want)
		}
	}
}

// BigInt256FromHex accepts 1 to 64 digits and an optional 0x, and gives zero otherwise.
func TestBigIntFromHexDifferential(t *testing.T) {
	reference := func(s string) (BigInt256, bool) {
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			s = s[2:]
		}
		if len(s) == 0 || len(s) > 64 {
			return BigInt256{}, false
		}
		if len(s)%2 == 1 {
			s = "0" + s
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return BigInt256{}, false
		}
		var padded [32]byte
		copy(padded[32-len(b):], b)
		var r BigInt256
		for i := 0; i < 4; i++ {
			off := (3 - i) * 8
			for j := 0; j < 8; j++ {
				r.limbs[i] = r.limbs[i]<<8 | uint64(padded[off+j])
			}
		}
		return r, true
	}
	rng := rand.New(rand.NewSource(23))
	for _, s := range hexInputs(rng) {
		want, ok := reference(s)
		got, err := BigInt256ParseHex(s)
		if (err == nil) != ok || got != want {
			t.Fatalf("BigInt256ParseHex(%q) = %x, %v", s, got.limbs, err)
		}
		if lenient := BigInt256FromHex(s); lenient != want {
			t.Fatalf("BigInt256FromHex(%q) = %x", s, lenient.limbs)
		}
	}
	x := BigInt256FromHex("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	if got := x.ToHex(); got != "0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210" {
		t.Errorf("ToHex = %s", got)
	}
	if got := x.ToHexLower(); got != "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210" {
		t.Errorf("ToHexLower = %s", got)
	}
}

// Key parsing takes either case; decodeHexLowerInto takes lowercase only.
func TestDecodeHexCase(t *testing.T) {
	rng := rand.New(rand.NewSource(25))
	for i := 0; i < 4000; i++ {
		raw := make([]byte, rng.Intn(40))
		rng.Read(raw)
		lower := hex.EncodeToString(raw)
		upper := strings.ToUpper(lower)
		got := make([]byte, len(raw))
		if !decodeHexLowerInto(got, lower) || string(got) != string(raw) {
			t.Fatalf("lowercase %s rejected", lower)
		}
		if !decodeHexInto(got, upper) || string(got) != string(raw) {
			t.Fatalf("uppercase %s rejected by the either-case decoder", upper)
		}
		if decodeHexLowerInto(got, upper) != (lower == upper) {
			t.Fatalf("uppercase %s accepted by the lowercase decoder", upper)
		}
	}
	// One uppercase letter at every position, including the unaligned tail.
	for n := 1; n < 40; n++ {
		s := []byte(strings.Repeat("a", 2*n))
		dst := make([]byte, n)
		for pos := range s {
			s[pos] = 'F'
			if decodeHexLowerInto(dst, string(s)) {
				t.Fatalf("length %d: uppercase at %d accepted", n, pos)
			}
			s[pos] = 'a'
		}
	}
}

// Point decoding accepts exactly the valid encoding, and no longer panics on anything.
func TestPointHexDecoding(t *testing.T) {
	g := ECPointGenerator().ToHexEncoded()
	if p := ECPointFromHexEncoded(g); !p.Equal(ECPointGenerator()) {
		t.Fatalf("generator did not decode: %+v", p.ToHexEncoded())
	}
	rng := rand.New(rand.NewSource(24))
	inputs := append(hexInputs(rng), g+"z", g+"0", g+"00", "z"+g, g[:129], g[:128], "05"+g[2:], g[:129]+"z", "00", "")
	for _, s := range inputs {
		if p := ECPointFromHexEncoded(s); !p.Infinity {
			t.Fatalf("ECPointFromHexEncoded(%q) accepted", s)
		}
		if _, err := SM2ParsePublicKey(s); err == nil {
			t.Fatalf("SM2ParsePublicKey(%q) accepted", s)
		}
	}
}
