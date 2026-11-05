package smx

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

type securityVectors struct {
	SM2 struct {
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
		UserID     string `json:"user_id"`
		Message    string `json:"message"`
		NonceK     string `json:"nonce_k"`
		R          string `json:"r"`
		S          string `json:"s"`
		Plaintext  string `json:"plaintext"`
		Ciphertext string `json:"ciphertext"`
		MaxPrivate string `json:"n_minus_2_is_max_valid_private_key"`
		BadPublic  []struct {
			Name, Value string
		} `json:"invalid_public_keys"`
		BadPrivate []struct {
			Name, Value string
		} `json:"invalid_private_keys"`
		BadSignatures []struct {
			Name, R, S string
		} `json:"invalid_signatures"`
		BadCiphertexts []struct {
			Name, Value string
		} `json:"invalid_ciphertexts"`
		UserIDMax   int `json:"user_id_max_bytes"`
		UserIDFirst int `json:"user_id_first_invalid_bytes"`
	} `json:"sm2"`
	SM3 struct {
		Zeros512  string `json:"zeros_512_mib"`
		Zeros1024 string `json:"zeros_1024_mib"`
	} `json:"sm3"`
	SM4 struct {
		Key             string `json:"key"`
		IV              string `json:"iv"`
		ValidCiphertext string `json:"valid_padded_ciphertext"`
		ValidPlaintext  string `json:"valid_padded_plaintext"`
		FullBlock       string `json:"valid_full_padding_block_ciphertext"`
		BadKeyLengths   []int  `json:"invalid_key_lengths_bytes"`
		BadIVLengths    []int  `json:"invalid_iv_lengths_bytes"`
		BadPaddings     []struct {
			Name, Value string
		} `json:"invalid_paddings"`
		BadLengths []int `json:"invalid_ciphertext_lengths_bytes"`
	} `json:"sm4"`
}

func loadSecurityVectors(t testing.TB) *securityVectors {
	t.Helper()
	data, err := os.ReadFile("../testvectors/security-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	v := new(securityVectors)
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
	if len(v.SM2.BadPublic) == 0 || len(v.SM2.BadPrivate) == 0 || len(v.SM2.BadSignatures) == 0 ||
		len(v.SM2.BadCiphertexts) == 0 || len(v.SM4.BadPaddings) == 0 {
		t.Fatal("vector file did not decode")
	}
	return v
}

func TestVectorsSM2Valid(t *testing.T) {
	v := loadSecurityVectors(t)
	d := BigInt256FromHex(v.SM2.PrivateKey)
	if got := SM2GetPublicKey(&d).ToHexEncoded(); got != v.SM2.PublicKey {
		t.Errorf("public key = %s", got)
	}
	k := BigInt256FromHex(v.SM2.NonceK)
	sig, ok := sm2SignWithNonce(v.SM2.UserID, v.SM2.Message, &d, &k)
	want := v.SM2.R + "h" + v.SM2.S
	if !ok || sig != want {
		t.Errorf("signature = %s", sig)
	}
	if !SM2Verify(v.SM2.UserID, want, v.SM2.Message, v.SM2.PublicKey) {
		t.Error("valid signature rejected")
	}
	pub, err := SM2ParsePublicKey(v.SM2.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ct, ok := sm2EncryptWithNonce(v.SM2.Plaintext, &pub, &k)
	if !ok || ct != v.SM2.Ciphertext {
		t.Errorf("ciphertext = %s", ct)
	}
	if got, err := SM2Decrypt(v.SM2.Ciphertext, v.SM2.PrivateKey); err != nil || got != v.SM2.Plaintext {
		t.Errorf("decrypt = %q, %v", got, err)
	}

	// n-2 is the largest valid private key, and it works.
	sig, err = SM2Sign("id", "m", v.SM2.MaxPrivate)
	if err != nil {
		t.Fatal(err)
	}
	maxKey := BigInt256FromHex(v.SM2.MaxPrivate)
	maxPub := SM2GetPublicKey(&maxKey).ToHexEncoded()
	if !SM2Verify("id", sig, "m", maxPub) {
		t.Error("signature with n-2 rejected")
	}
}

func TestVectorsInvalidPublicKeys(t *testing.T) {
	v := loadSecurityVectors(t)
	sig := v.SM2.R + "h" + v.SM2.S
	d := BigInt256FromHex(v.SM2.PrivateKey)
	good := SM2DecodePoint(v.SM2.PublicKey)
	for _, tc := range v.SM2.BadPublic {
		t.Run(tc.Name, func(t *testing.T) {
			if _, err := SM2ParsePublicKey(tc.Value); err == nil {
				t.Error("SM2ParsePublicKey accepted")
			}
			if p := SM2DecodePoint(tc.Value); !p.Infinity || p.IsOnCurve() {
				t.Error("SM2DecodePoint accepted")
			}
			if _, err := SM2Encrypt("message", tc.Value); err == nil {
				t.Error("SM2Encrypt accepted")
			}
			if SM2Verify(v.SM2.UserID, sig, v.SM2.Message, tc.Value) {
				t.Error("SM2Verify accepted")
			}
			bad := SM2DecodePoint(tc.Value)
			for i, set := range [][4]ECPoint{{bad, good, good, good}, {good, bad, good, good}, {good, good, bad, good}, {good, good, good, bad}} {
				if r := SM2GetSb(16, set[0], set[1], set[2], &d, set[3], &d, "a", "b"); r.Success {
					t.Errorf("SM2GetSb accepted in position %d", i)
				}
				if r := SM2GetSa(16, set[0], set[1], set[2], &d, set[3], &d, "a", "b", make([]byte, 32)); r.Success {
					t.Errorf("SM2GetSa accepted in position %d", i)
				}
			}
		})
	}
}

func TestVectorsInvalidPrivateKeys(t *testing.T) {
	v := loadSecurityVectors(t)
	good := SM2DecodePoint(v.SM2.PublicKey)
	for _, tc := range v.SM2.BadPrivate {
		t.Run(tc.Name, func(t *testing.T) {
			if _, err := parsePrivateKey(tc.Value); err == nil {
				t.Error("parsePrivateKey accepted")
			}
			if _, err := SM2Sign(v.SM2.UserID, v.SM2.Message, tc.Value); err == nil {
				t.Error("SM2Sign accepted")
			}
			if _, err := SM2Decrypt(v.SM2.Ciphertext, tc.Value); err == nil {
				t.Error("SM2Decrypt accepted")
			}
			k := BigInt256FromHex(tc.Value)
			if p := SM2GetPublicKey(&k); !p.Infinity {
				t.Error("SM2GetPublicKey accepted")
			}
			d := BigInt256FromHex(v.SM2.PrivateKey)
			if r := SM2GetSb(16, good, good, good, &k, good, &d, "a", "b"); r.Success {
				t.Error("SM2GetSb accepted dB")
			}
			if r := SM2GetSb(16, good, good, good, &d, good, &k, "a", "b"); r.Success {
				t.Error("SM2GetSb accepted rb")
			}
			if r := SM2GetSa(16, good, good, good, &k, good, &d, "a", "b", make([]byte, 32)); r.Success {
				t.Error("SM2GetSa accepted dA")
			}
			if r := SM2GetSa(16, good, good, good, &d, good, &k, "a", "b", make([]byte, 32)); r.Success {
				t.Error("SM2GetSa accepted ra")
			}
		})
	}
}

func TestVectorsInvalidSignatures(t *testing.T) {
	v := loadSecurityVectors(t)
	for _, tc := range v.SM2.BadSignatures {
		t.Run(tc.Name, func(t *testing.T) {
			if SM2Verify(v.SM2.UserID, tc.R+"h"+tc.S, v.SM2.Message, v.SM2.PublicKey) {
				t.Error("accepted")
			}
		})
	}
	for _, sig := range []string{"", "h", v.SM2.R, v.SM2.R + v.SM2.S, v.SM2.R + "H" + v.SM2.S,
		"0x" + v.SM2.R + "h" + v.SM2.S, v.SM2.R + "h" + v.SM2.S + "h", " " + v.SM2.R + "h" + v.SM2.S,
		strings.Repeat("h", 129)} {
		if SM2Verify(v.SM2.UserID, sig, v.SM2.Message, v.SM2.PublicKey) {
			t.Errorf("accepted %q", sig)
		}
	}
}

func TestVectorsInvalidCiphertexts(t *testing.T) {
	v := loadSecurityVectors(t)
	for _, tc := range v.SM2.BadCiphertexts {
		t.Run(tc.Name, func(t *testing.T) {
			if got, err := SM2Decrypt(tc.Value, v.SM2.PrivateKey); err == nil {
				t.Errorf("accepted, plaintext %q", got)
			}
		})
	}
}

func TestVectorsUserIDLength(t *testing.T) {
	v := loadSecurityVectors(t)
	maxID := strings.Repeat("a", v.SM2.UserIDMax)
	tooLong := strings.Repeat("a", v.SM2.UserIDFirst)
	sig, err := SM2Sign(maxID, v.SM2.Message, v.SM2.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !SM2Verify(maxID, sig, v.SM2.Message, v.SM2.PublicKey) {
		t.Error("8191-byte ID rejected")
	}
	if _, err := SM2Sign(tooLong, v.SM2.Message, v.SM2.PrivateKey); err == nil {
		t.Error("SM2Sign accepted 8192-byte ID")
	}
	if SM2Verify(tooLong, sig, v.SM2.Message, v.SM2.PublicKey) {
		t.Error("SM2Verify accepted 8192-byte ID")
	}
	// 65536 bytes would wrap ENTL to zero, so an empty ID and this one must not collide.
	if SM2Verify(strings.Repeat("a", 65536), sig, v.SM2.Message, v.SM2.PublicKey) {
		t.Error("SM2Verify accepted a wrapping ID")
	}
	p := SM2DecodePoint(v.SM2.PublicKey)
	d := BigInt256FromHex(v.SM2.PrivateKey)
	if r := SM2GetSb(16, p, p, p, &d, p, &d, tooLong, "b"); r.Success {
		t.Error("SM2GetSb accepted long idA")
	}
	if r := SM2GetSa(16, p, p, p, &d, p, &d, "a", tooLong, make([]byte, 32)); r.Success {
		t.Error("SM2GetSa accepted long idB")
	}
}

func TestVectorsSM3LongMessages(t *testing.T) {
	if testing.Short() {
		t.Skip("hashes 1.5 GiB")
	}
	v := loadSecurityVectors(t)
	chunk := make([]byte, 1<<20)
	h := NewSM3()
	for i := 0; i < 512; i++ {
		h.Update(chunk)
	}
	h.Finish()
	if got := strings.ToLower(h.HashHexUpper()); got != v.SM3.Zeros512 {
		t.Errorf("512 MiB = %s", got)
	}
	for i := 0; i < 1024; i++ {
		h.Update(chunk)
	}
	h.Finish()
	if got := strings.ToLower(h.HashHexUpper()); got != v.SM3.Zeros1024 {
		t.Errorf("1024 MiB = %s", got)
	}
}

func TestVectorsSM4(t *testing.T) {
	v := loadSecurityVectors(t)
	key, _ := hex.DecodeString(v.SM4.Key)
	iv, _ := hex.DecodeString(v.SM4.IV)

	s := NewSM4()
	if err := s.TrySetKey(key, iv); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Encrypt(v.SM4.ValidPlaintext); err != nil || got != v.SM4.ValidCiphertext {
		t.Errorf("Encrypt = %s, %v", got, err)
	}
	if got, err := s.Decrypt(v.SM4.ValidCiphertext); err != nil || got != v.SM4.ValidPlaintext {
		t.Errorf("Decrypt = %q, %v", got, err)
	}
	// A block of nothing but padding is a valid encryption of the empty message.
	if got, err := s.Decrypt(v.SM4.FullBlock); err != nil || got != "" {
		t.Errorf("full padding block = %q, %v", got, err)
	}
	for _, tc := range v.SM4.BadPaddings {
		if got, err := s.Decrypt(tc.Value); err != errSM4Decrypt {
			t.Errorf("%s: %q, %v", tc.Name, got, err)
		}
	}
	for _, n := range v.SM4.BadLengths {
		if got, err := s.Decrypt(strings.Repeat("00", n)); err != errSM4Decrypt {
			t.Errorf("length %d: %q, %v", n, got, err)
		}
	}
	for _, n := range v.SM4.BadKeyLengths {
		checkSM4Rejected(t, make([]byte, n), iv)
	}
	for _, n := range v.SM4.BadIVLengths {
		checkSM4Rejected(t, key, make([]byte, n))
	}
}

func checkSM4Rejected(t *testing.T, key, iv []byte) {
	t.Helper()
	s := NewSM4()
	if err := s.TrySetKey(key, iv); err == nil {
		t.Errorf("TrySetKey accepted key %d, IV %d bytes", len(key), len(iv))
	}
	// A rejected SetKey also removes a key set earlier.
	s = NewSM4()
	s.SetKey(make([]byte, 16), make([]byte, 16))
	s.SetKey(key, iv)
	if _, err := s.Encrypt("x"); err == nil {
		t.Errorf("Encrypt ran after bad key %d, IV %d bytes", len(key), len(iv))
	}
	if s.keys != nil {
		t.Error("key material kept after failed SetKey")
	}
}

func TestSM4NoKey(t *testing.T) {
	for name, s := range map[string]*SM4{"new": NewSM4(), "zero": {}, "nil": nil} {
		if _, err := s.Encrypt("x"); err != errSM4KeyNotSet {
			t.Errorf("%s: Encrypt: %v", name, err)
		}
		if _, err := s.Decrypt(strings.Repeat("00", 16)); err != errSM4KeyNotSet {
			t.Errorf("%s: Decrypt: %v", name, err)
		}
	}
	var s *SM4
	s.SetKey(make([]byte, 16), make([]byte, 16)) // must not crash
}

// sm4StandardSBox is the table from GB/T 32907. It exists only to check the circuit.
var sm4StandardSBox = [256]byte{
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
}

func TestSM4CircuitAllInputs(t *testing.T) {
	for x := 0; x < 256; x++ {
		// In every byte position of the word, and with the other positions different.
		for pos := uint(0); pos < 4; pos++ {
			in := uint32(x)<<(8*pos) | uint32(0x5A)<<(8*((pos+1)%4))
			got := sm4Tau(in)
			if byte(got>>(8*pos)) != sm4StandardSBox[x] {
				t.Fatalf("S(%#x) at byte %d = %#x, want %#x", x, pos, byte(got>>(8*pos)), sm4StandardSBox[x])
			}
			if byte(got>>(8*((pos+1)%4))) != sm4StandardSBox[0x5A] {
				t.Fatalf("neighbor of S(%#x) at byte %d corrupted", x, pos)
			}
		}
	}
	// All 64 lanes of the full-width circuit.
	for x := 0; x < 256; x++ {
		var in [8]uint64
		for bit := 0; bit < 8; bit++ {
			if x>>bit&1 == 1 {
				in[bit] = ^uint64(0)
			}
		}
		y0, y1, y2, y3, y4, y5, y6, y7 := sm4SBoxCircuit(in[0], in[1], in[2], in[3], in[4], in[5], in[6], in[7])
		for lane := uint(0); lane < 64; lane++ {
			var got byte
			for bit, y := range [8]uint64{y0, y1, y2, y3, y4, y5, y6, y7} {
				got |= byte(y>>lane&1) << bit
			}
			if got != sm4StandardSBox[x] {
				t.Fatalf("lane %d: S(%#x) = %#x", lane, x, got)
			}
		}
	}
}

// The batch must match the single-block rounds in every block position, and CBC
// decryption must match for every length around the batch thresholds.
func TestSM4BatchMatchesSingle(t *testing.T) {
	s := NewSM4()
	s.SetKey(benchData(16), benchData(16))
	var batch [sm4BatchBlocks * sm4BlockSize]byte
	copy(batch[:], benchData(len(batch)))
	want := batch
	for off := 0; off < len(want); off += 16 {
		w := want[off : off+16]
		x0, x1, x2, x3 := sm4EncryptWords(&s.keys.rk, be32(w), be32(w[4:]), be32(w[8:]), be32(w[12:]))
		put32(w, x0)
		put32(w[4:], x1)
		put32(w[8:], x2)
		put32(w[12:], x3)
	}
	sm4CryptBatch(&s.keys.rk, &batch)
	if batch != want {
		t.Fatal("batch differs from single-block rounds")
	}
	for blocks := 1; blocks <= 70; blocks++ {
		plain := benchData(blocks * 16)
		ct := append([]byte(nil), plain...)
		sm4CBCEncryptGeneric(&s.keys.rk, &s.keys.iv, ct)
		sm4CBCDecryptGeneric(&s.keys.drk, &s.keys.iv, ct)
		if string(ct) != string(plain) {
			t.Fatalf("%d blocks: round trip failed", blocks)
		}
	}
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func put32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}

// Every padded length and every wrong byte, against a simple reference.
func TestPKCS7Exhaustive(t *testing.T) {
	reference := func(b []byte) (int, bool) {
		p := int(b[len(b)-1])
		if p == 0 || p > 16 {
			return 0, false
		}
		for _, c := range b[len(b)-p:] {
			if int(c) != p {
				return 0, false
			}
		}
		return p, true
	}
	check := func(b []byte) {
		wantLen, wantOK := reference(b)
		gotLen, mask := pkcs7Check(b)
		if mask != 0 && mask != ^uint64(0) {
			t.Fatalf("pkcs7Check(%x) mask = %x", b, mask)
		}
		if (mask != 0) != wantOK || (wantOK && int(gotLen) != wantLen) {
			t.Fatalf("pkcs7Check(%x) = %d, %x", b, gotLen, mask)
		}
	}
	for last := 0; last < 256; last++ {
		b := make([]byte, 16)
		for i := range b {
			b[i] = byte(last)
		}
		check(b)
		for pos := 0; pos < 15; pos++ {
			for _, v := range []byte{0, 1, 16, 17, byte(last) ^ 1, byte(last) ^ 0x80, 0xFF} {
				mut := append([]byte(nil), b...)
				mut[pos] = v
				check(mut)
			}
		}
		check(append(make([]byte, 16), b...))
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

type constantReader byte

func (r constantReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(r)
	}
	return len(b), nil
}

// shortReader gives one byte and then fails, which must not count as success.
type shortReader struct{ used bool }

func (r *shortReader) Read(b []byte) (int, error) {
	if r.used {
		return 0, errors.New("exhausted")
	}
	r.used = true
	b[0] = 1
	return 1, nil
}

func withRandReader(t *testing.T, r interface{ Read([]byte) (int, error) }, f func()) {
	t.Helper()
	saved := sm2RandReader
	sm2RandReader = r
	defer func() { sm2RandReader = saved }()
	f()
}

func TestRandomFailureIsClean(t *testing.T) {
	v := loadSecurityVectors(t)
	for name, r := range map[string]interface{ Read([]byte) (int, error) }{
		"error":     failingReader{errors.New("no entropy")},
		"short":     &shortReader{},
		"all zeros": constantReader(0),
		"all ones":  constantReader(0xFF), // always above n, so rejection never ends by itself
	} {
		t.Run(name, func(t *testing.T) {
			withRandReader(t, r, func() {
				if priv, pub := SM2GenKeyPair(); priv != "" || pub != "" {
					t.Error("SM2GenKeyPair returned a key")
				}
				if _, _, err := SM2GenerateKeyPair(); err != errRandom {
					t.Errorf("SM2GenerateKeyPair: %v", err)
				}
				if _, err := SM2Sign("id", "m", v.SM2.PrivateKey); err != errRandom {
					t.Errorf("SM2Sign: %v", err)
				}
				if _, err := SM2Encrypt("m", v.SM2.PublicKey); err != errRandom {
					t.Errorf("SM2Encrypt: %v", err)
				}
			})
		})
	}
}

func TestKeyGenerationRange(t *testing.T) {
	for i := 0; i < 100; i++ {
		priv, pub, err := SM2GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		d, err := parsePrivateKey(priv)
		if err != nil {
			t.Fatalf("generated invalid key: %v", err)
		}
		if got := SM2GetPublicKey(&d).ToHexEncoded(); got != pub {
			t.Fatal("public key mismatch")
		}
	}
	// Private key boundaries.
	cases := map[string]bool{
		"0000000000000000000000000000000000000000000000000000000000000001": true,
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54121": true,
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122": false,
		"0x00000000000000000000000000000000000000000000000000000000000001": false,
		"1": false,
	}
	for key, want := range cases {
		if _, err := parsePrivateKey(key); (err == nil) != want {
			t.Errorf("parsePrivateKey(%s): %v", key, err)
		}
	}
}

func TestKDFAndLengthLimits(t *testing.T) {
	if sm2PlaintextLenValid(sm2MaxKDFBytes + 1) {
		t.Error("KDF limit not enforced")
	}
	if !sm2PlaintextLenValid(1 << 20) {
		t.Error("ordinary length rejected")
	}
	if _, ok := sm4PaddedSize(-1); ok {
		t.Error("negative SM4 size accepted")
	}
	if _, ok := sm4PaddedSize(int(^uint(0) >> 1)); ok {
		t.Error("overflowing SM4 size accepted")
	}
	if n, ok := sm4PaddedSize(16); !ok || n != 32 {
		t.Errorf("sm4PaddedSize(16) = %d, %v", n, ok)
	}

	// All-zero KDF output is detected.
	dst := make([]byte, 32)
	if kdfXOR(dst, dst, []byte("seed")) {
		t.Error("real KDF output reported as all zero")
	}
	if !kdfXOR(nil, nil, []byte("seed")) {
		t.Error("empty KDF output should count as all zero")
	}

	// Key exchange key lengths.
	v := loadSecurityVectors(t)
	p := SM2DecodePoint(v.SM2.PublicKey)
	d := BigInt256FromHex(v.SM2.PrivateKey)
	for _, n := range []int{-1, 0, 1<<20 + 1, int(^uint(0) >> 1)} {
		if r := SM2GetSb(n, p, p, p, &d, p, &d, "a", "b"); r.Success {
			t.Errorf("SM2GetSb accepted key length %d", n)
		}
		if r := SM2GetSa(n, p, p, p, &d, p, &d, "a", "b", make([]byte, 32)); r.Success {
			t.Errorf("SM2GetSa accepted key length %d", n)
		}
	}
	if r := SM2GetSb(1<<20, p, p, p, &d, p, &d, "a", "b"); !r.Success && r.Message == "invalid key length" {
		t.Error("1 MiB key rejected")
	}
}

func TestKeyExchangeRejectsBadConfirmation(t *testing.T) {
	v := loadSecurityVectors(t)
	dA := BigInt256FromHex(v.SM2.PrivateKey)
	ra := BigInt256FromHex(v.SM2.NonceK)
	dB := BigInt256FromHex(benchPrivateKey)
	rb := BigInt256FromHex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80")
	pA, rA := SM2GetPublicKey(&dA), SM2GetPublicKey(&ra)
	pB, rB := SM2GetPublicKey(&dB), SM2GetPublicKey(&rb)
	resB := SM2GetSb(16, pA, rA, pB, &dB, rB, &rb, "a", "b")
	if !resB.Success {
		t.Fatal(resB.Message)
	}
	sb, _ := hexToBytes(resB.Sb)
	for _, bad := range [][]byte{nil, {}, sb[:31], append(append([]byte(nil), sb...), 0)} {
		if r := SM2GetSa(16, pB, rB, pA, &dA, rA, &ra, "a", "b", bad); r.Success || r.Ka != "" {
			t.Errorf("SM2GetSa accepted Sb of %d bytes", len(bad))
		}
	}
	resA := SM2GetSa(16, pB, rB, pA, &dA, rA, &ra, "a", "b", sb)
	if !resA.Success || resA.Ka != resB.Kb {
		t.Fatal("exchange failed")
	}
	sa, _ := hexToBytes(resA.Sa)
	if !SM2CheckSa(*resB.V, resB.Za, resB.Zb, rA, rB, sa) {
		t.Fatal("valid Sa rejected")
	}
	inf := ECPointInfinity()
	for i, c := range []struct {
		v, ra, rb ECPoint
		za, zb    []byte
		sa        []byte
	}{
		{*resB.V, rA, rB, resB.Za, resB.Zb, nil},
		{*resB.V, rA, rB, resB.Za, resB.Zb, sa[:31]},
		{inf, rA, rB, resB.Za, resB.Zb, sa},
		{*resB.V, inf, rB, resB.Za, resB.Zb, sa},
		{*resB.V, rA, inf, resB.Za, resB.Zb, sa},
		{*resB.V, rA, rB, nil, resB.Zb, sa},
		{*resB.V, rA, rB, resB.Za, resB.Zb[:31], sa},
	} {
		if SM2CheckSa(c.v, c.za, c.zb, c.ra, c.rb, c.sa) {
			t.Errorf("SM2CheckSa accepted case %d", i)
		}
	}
	if r := SM2GetSb(16, pA, rA, pB, nil, rB, &rb, "a", "b"); r.Success {
		t.Error("nil dB accepted")
	}
	if r := SM2GetSa(16, pB, rB, pA, &dA, rA, nil, "a", "b", sb); r.Success {
		t.Error("nil ra accepted")
	}
}

// Over many exchanges, x and y with leading zero bytes must still work, because all
// encodings are fixed width.
func TestKeyExchangeManyRandom(t *testing.T) {
	n := 300
	if testing.Short() {
		n = 30
	}
	for i := 0; i < n; i++ {
		dAh, _, _ := SM2GenerateKeyPair()
		raH, _, _ := SM2GenerateKeyPair()
		dBh, _, _ := SM2GenerateKeyPair()
		rbH, _, _ := SM2GenerateKeyPair()
		dA, ra, dB, rb := BigInt256FromHex(dAh), BigInt256FromHex(raH), BigInt256FromHex(dBh), BigInt256FromHex(rbH)
		pA, rA, pB, rB := SM2GetPublicKey(&dA), SM2GetPublicKey(&ra), SM2GetPublicKey(&dB), SM2GetPublicKey(&rb)
		resB := SM2GetSb(16, pA, rA, pB, &dB, rB, &rb, "a", "b")
		sb, _ := hexToBytes(resB.Sb)
		resA := SM2GetSa(16, pB, rB, pA, &dA, rA, &ra, "a", "b", sb)
		sa, _ := hexToBytes(resA.Sa)
		if !resB.Success || !resA.Success || resA.Ka != resB.Kb || !SM2CheckSa(*resB.V, resB.Za, resB.Zb, rA, rB, sa) {
			t.Fatalf("exchange %d failed: %s %s", i, resB.Message, resA.Message)
		}
	}
}

func TestSM3Limits(t *testing.T) {
	// Lengths at the 32-bit boundary go into the padding in full.
	h := SM3{v: sm3IV, ready: true, dataBitsLen: 1 << 32}
	h.Finish()
	plain := NewSM3()
	plain.Finish()
	if h.HashHexUpper() == plain.HashHexUpper() {
		t.Error("high length bits ignored")
	}

	// One byte past the limit yields no digest; the instance then works normally.
	h = SM3{v: sm3IV, ready: true, dataBitsLen: sm3MaxBytes * 8}
	h.UpdateByte(0)
	h.Finish()
	if h.HashHexUpper() != "" || h.HashBytes() != ([32]byte{}) {
		t.Error("digest produced past the length limit")
	}
	if _, err := h.Digest(); err != errSM3TooLong {
		t.Errorf("Digest past the limit: %v", err)
	}
	h.Finish() // must not turn the failure into the digest of an empty message
	if h.HashHexUpper() != "" {
		t.Error("second Finish hid the length failure")
	}
	h = SM3{v: sm3IV, ready: true, dataBitsLen: (sm3MaxBytes - 1) * 8}
	h.Update(make([]byte, 2))
	h.Finish()
	if h.HashHexUpper() != "" {
		t.Error("digest produced past the length limit by Update")
	}
	h.Update([]byte("abc"))
	h.Finish()
	if !strings.HasPrefix(h.HashHexUpper(), "66C7F0F4") {
		t.Errorf("instance not reusable: %s", h.HashHexUpper())
	}
	h = SM3{v: sm3IV, ready: true, dataBitsLen: (sm3MaxBytes - 1) * 8}
	h.UpdateByte(0)
	h.Finish()
	if h.HashHexUpper() == "" {
		t.Error("message of exactly the limit rejected")
	}

	// The zero value and nil.
	var zero SM3
	zero.Update([]byte("abc"))
	zero.Finish()
	if !strings.HasPrefix(zero.HashHexUpper(), "66C7F0F4") {
		t.Errorf("zero value gave %s", zero.HashHexUpper())
	}
	var zero2 SM3
	zero2.UpdateByte('a')
	zero2.Finish()
	want := NewSM3()
	want.Update([]byte("a"))
	want.Finish()
	if zero2.HashHexUpper() != want.HashHexUpper() {
		t.Error("zero value with UpdateByte differs")
	}
	var zero3 SM3
	zero3.Finish()
	if !strings.HasPrefix(zero3.HashHexUpper(), "1AB21D83") {
		t.Errorf("zero value empty digest %s", zero3.HashHexUpper())
	}
	var nilHash *SM3
	nilHash.Update([]byte("x"))
	nilHash.UpdateByte(1)
	nilHash.Finish()
	if nilHash.HashHexUpper() != "" || nilHash.HashBytes() != ([32]byte{}) {
		t.Error("nil SM3 produced output")
	}
}

// Changing the exported curve variables must not change the library's behavior.
func TestExportedCurveVariablesAreNotTrusted(t *testing.T) {
	v := loadSecurityVectors(t)
	savedP, savedN, savedA, savedB, savedGX, savedGY := SM2_P, SM2_N, SM2_A, SM2_B, SM2_GX, SM2_GY
	defer func() { SM2_P, SM2_N, SM2_A, SM2_B, SM2_GX, SM2_GY = savedP, savedN, savedA, savedB, savedGX, savedGY }()
	SM2_P, SM2_N = BigInt256{limbs: [4]uint64{7}}, BigInt256{limbs: [4]uint64{7}}
	SM2_A, SM2_B, SM2_GX, SM2_GY = FpOne(), FpOne(), FpOne(), FpOne()

	if !SM2Verify(v.SM2.UserID, v.SM2.R+"h"+v.SM2.S, v.SM2.Message, v.SM2.PublicKey) {
		t.Error("verification changed")
	}
	if got, err := SM2Decrypt(v.SM2.Ciphertext, v.SM2.PrivateKey); err != nil || got != v.SM2.Plaintext {
		t.Errorf("decryption changed: %v", err)
	}
	d := BigInt256FromHex(v.SM2.PrivateKey)
	if got := SM2GetPublicKey(&d).ToHexEncoded(); got != v.SM2.PublicKey {
		t.Error("key derivation changed")
	}
	if !ECPointGenerator().IsOnCurve() {
		t.Error("generator changed")
	}
}

// The bad-padding path must run the same step over the same bytes as the good one: here,
// the masking pass that keeps or erases the whole buffer. An early return would leave
// the bad buffer intact, which this detects.
func TestSM4UnpadSameWork(t *testing.T) {
	for _, n := range []int{16, 32, 48, 256, 1024} {
		good := bytes.Repeat([]byte{0xA5}, n)
		for i := n - 3; i < n; i++ {
			good[i] = 3
		}
		plain, ok := sm4Unpad(good)
		if !ok || len(plain) != n-3 || plain[0] != 0xA5 {
			t.Fatalf("n=%d: good padding: %d bytes, %v", n, len(plain), ok)
		}
		for _, badByte := range []byte{0, 17, 0xFF} {
			bad := bytes.Repeat([]byte{0xA5}, n)
			bad[n-1] = badByte
			if _, ok := sm4Unpad(bad); ok {
				t.Fatalf("n=%d: bad padding %#x accepted", n, badByte)
			}
			if !bytes.Equal(bad, make([]byte, n)) {
				t.Fatalf("n=%d: bad padding %#x skipped the masking pass", n, badByte)
			}
		}
		// A wrong byte inside otherwise plausible padding.
		bad := bytes.Repeat([]byte{4}, n)
		bad[n-3] = 9
		if _, ok := sm4Unpad(bad); ok || !bytes.Equal(bad, make([]byte, n)) {
			t.Fatalf("n=%d: inconsistent padding handled differently", n)
		}
	}
	for _, n := range []int{0, 1, 7, 8, 9, 15, 16, 17, 100} {
		b := bytes.Repeat([]byte{0xC3}, n)
		maskBytes(b, ^uint64(0))
		if !bytes.Equal(b, bytes.Repeat([]byte{0xC3}, n)) {
			t.Fatalf("maskBytes keep, %d bytes", n)
		}
		maskBytes(b, 0)
		if !bytes.Equal(b, make([]byte, n)) {
			t.Fatalf("maskBytes erase, %d bytes", n)
		}
	}
}

// One signature or ciphertext has one accepted string form. Keys take either case.
func TestCanonicalLowercase(t *testing.T) {
	v := loadSecurityVectors(t)
	sig := v.SM2.R + "h" + v.SM2.S
	if !SM2Verify(v.SM2.UserID, sig, v.SM2.Message, v.SM2.PublicKey) {
		t.Fatal("valid signature rejected")
	}
	for _, bad := range []string{strings.ToUpper(v.SM2.R) + "h" + v.SM2.S, v.SM2.R + "h" + strings.ToUpper(v.SM2.S),
		strings.ToUpper(sig), v.SM2.R[:63] + strings.ToUpper(v.SM2.R[63:]) + "h" + v.SM2.S} {
		if bad != sig && SM2Verify(v.SM2.UserID, bad, v.SM2.Message, v.SM2.PublicKey) {
			t.Errorf("accepted %s", bad)
		}
	}
	ct := v.SM2.Ciphertext
	for name, bad := range map[string]string{
		"all": strings.ToUpper(ct),
		"c1":  strings.ToUpper(ct[:130]) + ct[130:],
		"c3":  ct[:130] + strings.ToUpper(ct[130:194]) + ct[194:],
		"c2":  ct[:194] + strings.ToUpper(ct[194:]),
	} {
		if bad == ct {
			t.Fatalf("%s: test value has no letters", name)
		}
		if _, err := SM2Decrypt(bad, v.SM2.PrivateKey); err == nil {
			t.Errorf("%s: uppercase ciphertext accepted", name)
		}
	}
	// Keys stay case-insensitive.
	upperKey := strings.ToUpper(v.SM2.PrivateKey)
	if got, err := SM2Decrypt(ct, upperKey); err != nil || got != v.SM2.Plaintext {
		t.Errorf("uppercase private key: %q, %v", got, err)
	}
	if !SM2Verify(v.SM2.UserID, sig, v.SM2.Message, strings.ToUpper(v.SM2.PublicKey)) {
		t.Error("uppercase public key rejected")
	}
	// The library's own output is lowercase.
	own, err := SM2Sign("id", "m", v.SM2.PrivateKey)
	if err != nil || own != strings.ToLower(own) {
		t.Errorf("SM2Sign output %s, %v", own, err)
	}
	enc, err := SM2Encrypt("m", v.SM2.PublicKey)
	if err != nil || enc != strings.ToLower(enc) {
		t.Errorf("SM2Encrypt output %s, %v", enc, err)
	}
}

func TestModPowZeroExponent(t *testing.T) {
	one, seven := BigInt256{limbs: [4]uint64{1}}, BigInt256{limbs: [4]uint64{7}}
	var zero BigInt256
	if got := zero.ModPow(&zero, &one); !got.IsZero() {
		t.Errorf("0^0 mod 1 = %s", got.ToHex())
	}
	if got := zero.ModPow(&zero, &seven); !got.IsOne() {
		t.Errorf("0^0 mod 7 = %s", got.ToHex())
	}
	p := BigInt256{limbs: curveP}
	if got := zero.ModPow(&zero, &p); !got.IsOne() {
		t.Errorf("0^0 mod p = %s", got.ToHex())
	}
}

// Keys must not reach output through any serializer or a struct holding the type.
func TestSecretsStayOutOfSerializers(t *testing.T) {
	v := loadSecurityVectors(t)
	dB := BigInt256FromHex(v.SM2.PrivateKey)
	rb := BigInt256FromHex(v.SM2.NonceK)
	pub := SM2DecodePoint(v.SM2.PublicKey)
	r := SM2GetSb(16, pub, pub, pub, &dB, pub, &rb, "a", "b")
	if !r.Success {
		t.Fatal(r.Message)
	}
	x := r.V.X.value.ToHexLower()
	leaks := func(where, out string) {
		t.Helper()
		lower := strings.ToLower(out)
		if strings.Contains(lower, r.Kb) || strings.Contains(lower, x) {
			t.Errorf("%s leaks a secret: %s", where, out)
		}
		for _, l := range append(r.V.X.value.limbs[:], dB.limbs[:]...) {
			if strings.Contains(out, fmt.Sprint(l)) {
				t.Errorf("%s leaks a limb: %s", where, out)
			}
		}
	}
	type exported struct {
		Params SM2KeySwapParams
		Point  ECPoint
		Elem   FpElement
		Key    BigInt256
		Ptr    *BigInt256
	}
	holder := exported{r, *r.V, r.V.X, dB, &dB}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%d"} {
		for name, value := range map[string]any{
			"params": r, "V pointer": r.V, "V": *r.V, "X": r.V.X, "key": dB, "holder": holder,
			"slice": []BigInt256{dB}, "map": map[string]ECPoint{"v": *r.V},
		} {
			leaks(name+" "+verb, fmt.Sprintf(verb, value))
		}
	}
	js, err := json.Marshal(holder)
	if err != nil {
		t.Fatal(err)
	}
	leaks("json", string(js))
	if strings.Contains(string(js), "Kb") {
		t.Errorf("json has Kb: %s", js)
	}
	xm, err := xml.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	leaks("xml", string(xm))
	if err := gob.NewEncoder(io.Discard).Encode(r); err == nil {
		t.Error("gob encoded the secrets")
	}

	// fmt cannot call methods in an unexported field. SM4 keys sit behind a pointer there.
	type unexported struct{ c SM4 }
	s := NewSM4()
	s.SetKey([]byte("0123456789abcdef"), []byte("fedcba9876543210"))
	roundKey := s.keys.rk[0]
	if out := fmt.Sprintf("%+v", unexported{*s}); strings.Contains(out, fmt.Sprint(roundKey)) || strings.Contains(out, "rk") {
		t.Errorf("SM4 in an unexported field leaks: %s", out)
	}
	if out := fmt.Sprintf("%+v", unexported{*s}); !strings.Contains(out, "0x") {
		t.Errorf("expected only an address: %s", out)
	}
}

// A copy made before re-keying must fail, not run with a wiped all-zero key.
func TestSM4StaleCopyFails(t *testing.T) {
	a := NewSM4()
	a.SetKey([]byte("0123456789abcdef"), []byte("fedcba9876543210"))
	b := *a
	if _, err := b.Encrypt("x"); err != nil {
		t.Fatalf("copy before re-key: %v", err)
	}
	a.SetKey([]byte("fedcba9876543210"), []byte("0123456789abcdef"))
	if _, err := b.Encrypt("x"); err != errSM4KeyNotSet {
		t.Errorf("stale copy Encrypt: %v", err)
	}
	if _, err := b.Decrypt(strings.Repeat("00", 16)); err != errSM4KeyNotSet {
		t.Errorf("stale copy Decrypt: %v", err)
	}
	if _, err := a.Encrypt("x"); err != nil {
		t.Errorf("re-keyed instance: %v", err)
	}
}

func TestSecretsStayOutOfFormatting(t *testing.T) {
	const keyHex = "3945208f7b2144b13f36e38ac6d39f95"
	full := keyHex + "889393692860b51a42fb81ef4df7c5b8"
	d := BigInt256FromHex(full)
	s := NewSM4()
	s.SetKey([]byte("0123456789abcdef"), []byte("fedcba9876543210"))
	h := NewSM3()
	h.Update([]byte("secret-message"))
	params := SM2KeySwapParams{Ka: "ka-secret", Kb: "kb-secret", Success: true}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%d", "%q"} {
		for _, value := range []any{d, &d, s, *s, h, *h, params, &params} {
			out := fmt.Sprintf(verb, value)
			lower := strings.ToLower(out)
			if strings.Contains(lower, "3945208f") || strings.Contains(lower, "3945") ||
				strings.Contains(out, "secret") || strings.Contains(lower, "736563726574") {
				t.Errorf("%s of %T leaks: %s", verb, value, out)
			}
			for _, limb := range d.limbs {
				if strings.Contains(out, fmt.Sprint(limb)) {
					t.Errorf("%s of %T leaks a limb", verb, value)
				}
			}
		}
	}
	// Errors carry no key material either.
	badKey := "zz" + full[2:]
	for _, err := range []error{
		errOnly(SM2Sign("id", "m", badKey)),
		errOnly(SM2Decrypt(loadSecurityVectors(t).SM2.Ciphertext, badKey)),
	} {
		if err == nil || strings.Contains(err.Error(), full[2:10]) || strings.Contains(err.Error(), "z") && strings.Contains(err.Error(), "U+") {
			t.Errorf("error leaks input: %v", err)
		}
	}
}

func errOnly(_ string, err error) error { return err }

func TestNilOperandsDoNotCrash(t *testing.T) {
	var a BigInt256
	a.limbs[0] = 5
	_ = a.Compare(nil)
	_, _ = a.Add(nil)
	_, _ = a.Sub(nil)
	_ = a.Mul(nil)
	_ = a.ModAdd(nil, nil)
	_ = a.ModSub(nil, nil)
	_ = a.ModMul(nil, nil)
	_ = a.ModSquare(nil)
	_ = a.SM2ModMulP(nil)
	_ = a.ModInverse(nil)
	_ = a.ModPow(nil, nil)
	_ = a.And(nil)
	if p := ECPointGenerator().Multiply(nil); !p.Infinity {
		t.Error("Multiply(nil) should give infinity")
	}
	if p := SM2GetPublicKey(nil); !p.Infinity {
		t.Error("SM2GetPublicKey(nil) should give infinity")
	}
	if got := BigInt256FromBEBytes(make([]byte, 33)); !got.IsZero() {
		t.Error("oversized bytes should give zero")
	}
	over := make([]byte, 33)
	over[32] = 1
	if got := BigInt256FromBEBytes(over); !got.IsZero() {
		t.Error("oversized bytes must not be truncated")
	}
}

// Multiplication by a secret must refuse an off-curve point.
func TestMultiplyRejectsInvalidCurvePoint(t *testing.T) {
	v := loadSecurityVectors(t)
	d := BigInt256FromHex(v.SM2.PrivateKey)
	off := NewECPoint(FpFromHex("3"), FpFromHex("5"))
	if off.IsOnCurve() {
		t.Fatal("test point is on the curve")
	}
	if p := off.Multiply(&d); !p.Infinity {
		t.Errorf("Multiply on an off-curve point returned %s", p.ToHexEncoded())
	}
}
