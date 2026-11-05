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
	reference := func(s string) ([]byte, error) {
		s = strings.TrimPrefix(s, "0x")
		s = strings.TrimPrefix(s, "0X")
		return hex.DecodeString(s)
	}
	for _, s := range hexInputs(rng) {
		got, gotErr := hexToBytes(s)
		want, wantErr := reference(s)
		if (gotErr == nil) != (wantErr == nil) || (gotErr != nil && gotErr.Error() != wantErr.Error()) {
			t.Fatalf("hexToBytes(%q) error = %v, want %v", s, gotErr, wantErr)
		}
		if string(got) != string(want) {
			t.Fatalf("hexToBytes(%q) = %x, want %x", s, got, want)
		}
	}
}

// BigInt256FromHex keeps its lenient parsing rules. This reference is the earlier code.
func TestBigIntFromHexDifferential(t *testing.T) {
	reference := func(s string) BigInt256 {
		s = strings.TrimPrefix(s, "0x")
		s = strings.TrimPrefix(s, "0X")
		if len(s)%2 == 1 {
			s = "0" + s
		}
		b, _ := hex.DecodeString(s)
		padded := make([]byte, 32)
		start := 32 - len(b)
		if start < 0 {
			start = 0
			b = b[len(b)-32:]
		}
		copy(padded[start:], b)
		var r BigInt256
		for i := 0; i < 4; i++ {
			off := (3 - i) * 8
			for j := 0; j < 8; j++ {
				r.limbs[i] = r.limbs[i]<<8 | uint64(padded[off+j])
			}
		}
		return r
	}
	rng := rand.New(rand.NewSource(23))
	for _, s := range hexInputs(rng) {
		if got, want := BigInt256FromHex(s), reference(s); got != want {
			t.Fatalf("BigInt256FromHex(%q) = %x, want %x", s, got.limbs, want.limbs)
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

// Decoding must panic and tolerate exactly as before.
func TestPointHexDecoding(t *testing.T) {
	reference := func(s string) (p ECPoint, panicked bool) {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		b, _ := hex.DecodeString(s)
		return ECPointFromEncoded(b), false
	}
	actual := func(s string) (p ECPoint, panicked bool) {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		return ECPointFromHexEncoded(s), false
	}
	g := ECPointGenerator().ToHexEncoded()
	rng := rand.New(rand.NewSource(24))
	inputs := append(hexInputs(rng), g, g+"z", g+"0", g+"00", "z"+g, g[:129], g[:128], "05"+g[2:], g[:129]+"z")
	for _, s := range inputs {
		gotP, gotPanic := actual(s)
		wantP, wantPanic := reference(s)
		if gotPanic != wantPanic || gotP != wantP {
			t.Fatalf("ECPointFromHexEncoded(%q) = %+v, panic %v; want %+v, panic %v", s, gotP, gotPanic, wantP, wantPanic)
		}
	}
}
