package smx

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	gbtPrivateKey = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
	gbtNonce      = "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21"
	gbtSignature  = "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3" +
		"h" + "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa"
	gbtCiphertext = "04" +
		"04ebfc718e8d179862043226" + "8e77feb6415e2ede0e073c0f" + "4f640ecd2e149a73" +
		"e858f9d81e5430a57b36daab" + "8f950a3c64e6ee6a63094d99" + "283aff767e124df0" +
		"59983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd8766" +
		"21886ca989ca9c7d58087307ca93092d651efa"
)

func kattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	return b
}

func sm3Upper(data []byte) string {
	h := NewSM3()
	h.Update(data)
	h.Finish()
	return h.HashHexUpper()
}

// GB/T 32905-2016, appendix A.
func TestSM3StandardVectors(t *testing.T) {
	tests := []struct{ in, want string }{
		{"abc", "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0"},
		{strings.Repeat("abcd", 16), "DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732"},
	}
	for _, tc := range tests {
		if got := sm3Upper([]byte(tc.in)); got != tc.want {
			t.Errorf("SM3(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestSM3CapturedVectors(t *testing.T) {
	for _, tc := range katSM3 {
		data := kattern(tc.n)
		if got := sm3Upper(data); got != tc.want {
			t.Errorf("SM3(len %d) = %s, want %s", tc.n, got, tc.want)
		}
		// Every chunking of the input must give the same digest.
		for _, chunk := range []int{1, 3, 7, 63, 64, 65} {
			h := NewSM3()
			rest := data
			for len(rest) > 0 {
				n := chunk
				if n > len(rest) {
					n = len(rest)
				}
				h.Update(rest[:n])
				rest = rest[n:]
			}
			h.Finish()
			if got := h.HashHexUpper(); got != tc.want {
				t.Errorf("SM3(len %d, chunk %d) = %s, want %s", tc.n, chunk, got, tc.want)
			}
		}
		h := NewSM3()
		for _, b := range data {
			h.UpdateByte(b)
		}
		h.Finish()
		if got := h.HashHexUpper(); got != tc.want {
			t.Errorf("SM3(len %d, UpdateByte) = %s, want %s", tc.n, got, tc.want)
		}
	}
}

func TestSM3LifeCycle(t *testing.T) {
	h := NewSM3()
	if got := h.HashHexUpper(); got != "" {
		t.Errorf("hex before Finish = %q, want empty", got)
	}
	if got := h.HashBytes(); got != ([32]byte{}) {
		t.Errorf("bytes before Finish = %x, want zero", got)
	}
	const abc = "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0"
	h.Update([]byte("abc"))
	h.Finish()
	// Finish keeps the digest available and resets the instance for reuse.
	h.Update([]byte("ignored until the next Finish"))
	if got := h.HashHexUpper(); got != abc {
		t.Errorf("hex after further Update = %s", got)
	}
	h = NewSM3()
	h.Update([]byte("first"))
	h.Finish()
	h.Update([]byte("abc"))
	h.Finish()
	if got := h.HashHexUpper(); got != abc {
		t.Errorf("reused instance = %s", got)
	}
	bytes := h.HashBytes()
	if strings.ToUpper(hex.EncodeToString(bytes[:])) != abc {
		t.Errorf("HashBytes = %x", bytes)
	}
}

// The first ciphertext block of CBC under a zero IV is the raw SM4 block output.
func sm4FirstBlock(t testing.TB, s *SM4, block []byte) []byte {
	t.Helper()
	ct, err := s.Encrypt(string(block))
	if err != nil {
		t.Fatal(err)
	}
	out, err := hex.DecodeString(ct[:32])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// GB/T 32907-2016, appendix A, examples 1 and 2 (the second is one million iterations).
func TestSM4StandardVectors(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv := make([]byte, 16)
	s := NewSM4()
	s.SetKey(key, iv)

	got := sm4FirstBlock(t, s, key)
	if hex.EncodeToString(got) != "681edf34d206965e86b3e94f536e4246" {
		t.Errorf("single block = %x", got)
	}

	if testing.Short() {
		t.Skip("skipping 1,000,000 iteration vector in -short mode")
	}
	block := append([]byte(nil), key...)
	for i := 0; i < 1000000; i++ {
		block = sm4FirstBlock(t, s, block)
	}
	if hex.EncodeToString(block) != "595298c7c6fd271f0402f804c33d3f66" {
		t.Errorf("1,000,000 iterations = %x", block)
	}
}

func TestSM4CapturedVectors(t *testing.T) {
	for _, tc := range katSM4 {
		s := NewSM4()
		s.SetKey([]byte(tc.key), []byte(tc.iv))
		plain := string(kattern(tc.n))
		ct, err := s.Encrypt(plain)
		if err != nil {
			t.Fatal(err)
		}
		if got := sm3Upper([]byte(ct)); got != tc.want {
			t.Errorf("key %q len %d: ciphertext digest = %s, want %s", tc.key, tc.n, got, tc.want)
		}
		dec, err := s.Decrypt(ct)
		if err != nil {
			t.Fatalf("key %q len %d: %v", tc.key, tc.n, err)
		}
		if dec != plain {
			t.Errorf("key %q len %d: round trip mismatch", tc.key, tc.n)
		}
	}
}

func TestSM4DecryptErrors(t *testing.T) {
	s := NewSM4()
	s.SetKey([]byte("0123456789abcdef"), []byte("fedcba9876543210"))
	if got, err := s.Decrypt(""); err != nil || got != "" {
		t.Errorf("empty ciphertext = %q, %v", got, err)
	}
	tests := []struct{ in, want string }{
		{"abc", "encoding/hex: odd length hex string"},
		{"zz", "encoding/hex: invalid byte: U+007A 'z'"},
		{"00", "invalid ciphertext length"},
		{strings.Repeat("00", 16), "invalid padding"},
	}
	for _, tc := range tests {
		_, err := s.Decrypt(tc.in)
		if err == nil || err.Error() != tc.want {
			t.Errorf("Decrypt(%q) error = %v, want %s", tc.in, err, tc.want)
		}
	}
	// The hex decoder accepts upper case and an optional 0x prefix.
	ct, _ := s.Encrypt("hello")
	for _, in := range []string{strings.ToUpper(ct), "0x" + ct, "0X" + ct} {
		if got, err := s.Decrypt(in); err != nil || got != "hello" {
			t.Errorf("Decrypt(%q) = %q, %v", in, got, err)
		}
	}
}

func TestMultiplyCapturedVectors(t *testing.T) {
	g := ECPointGenerator()
	d := BigInt256FromHex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE")
	p := g.Multiply(&d)
	for _, tc := range katMultiply {
		k := BigInt256FromHex(tc.k)
		if got := g.Multiply(&k).ToHexEncoded(); got != tc.g {
			t.Errorf("[%s]G = %s, want %s", tc.k, got, tc.g)
		}
		if got := p.Multiply(&k).ToHexEncoded(); got != tc.p {
			t.Errorf("[%s]P = %s, want %s", tc.k, got, tc.p)
		}
	}
}

func TestSM2StandardVectors(t *testing.T) {
	d := BigInt256FromHex(gbtPrivateKey)
	pub := SM2GetPublicKey(&d).ToHexEncoded()
	if !SM2Verify("1234567812345678", gbtSignature, "message digest", pub) {
		t.Error("GB/T 32918.5 signature rejected")
	}
	if SM2Verify("1234567812345678", gbtSignature, "message digesT", pub) {
		t.Error("signature accepted for a different message")
	}
	got, err := SM2Decrypt(gbtCiphertext, gbtPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if got != "encryption standard" {
		t.Errorf("decrypted %q", got)
	}
}

func TestSM2CapturedCiphertexts(t *testing.T) {
	for _, tc := range katSM2Encrypt {
		got, err := SM2Decrypt(tc.want, tc.d)
		if err != nil {
			t.Fatalf("d=%s k=%s n=%d: %v", tc.d, tc.k, tc.n, err)
		}
		if got != string(kattern(tc.n)) {
			t.Errorf("d=%s k=%s n=%d: wrong plaintext", tc.d, tc.k, tc.n)
		}
	}
}

func TestSM2CapturedSignatures(t *testing.T) {
	for _, tc := range katSM2Sign {
		d := BigInt256FromHex(tc.d)
		pub := SM2GetPublicKey(&d).ToHexEncoded()
		if !SM2Verify(tc.id, tc.want, tc.msg, pub) {
			t.Errorf("d=%s k=%s id=%q: signature rejected", tc.d, tc.k, tc.id)
		}
		if SM2Verify(tc.id+"x", tc.want, tc.msg, pub) {
			t.Errorf("d=%s k=%s id=%q: accepted for wrong id", tc.d, tc.k, tc.id)
		}
	}
}

func TestKeyExchangeCaptured(t *testing.T) {
	idA, idB := "ALICE123@YAHOO.COM", "BILL456@YAHOO.COM"
	dA := BigInt256FromHex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE")
	ra := BigInt256FromHex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563")
	dB := BigInt256FromHex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53")
	rb := BigInt256FromHex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80")
	pA, rA := SM2GetPublicKey(&dA), SM2GetPublicKey(&ra)
	pB, rB := SM2GetPublicKey(&dB), SM2GetPublicKey(&rb)
	for _, tc := range katKeyExchange {
		resB := SM2GetSb(tc.n, pA, rA, pB, &dB, rB, &rb, idA, idB)
		if !resB.Success || resB.Sb != tc.sb || resB.Kb != tc.kb || resB.V.ToHexEncoded() != tc.vv {
			t.Errorf("n=%d: SM2GetSb = %+v", tc.n, resB)
			continue
		}
		sb, _ := hexToBytes(tc.sb)
		resA := SM2GetSa(tc.n, pB, rB, pA, &dA, rA, &ra, idA, idB, sb)
		if !resA.Success || resA.Sa != tc.sa || resA.Ka != tc.ka {
			t.Errorf("n=%d: SM2GetSa = %+v", tc.n, resA)
			continue
		}
		sa, _ := hexToBytes(tc.sa)
		if !SM2CheckSa(*resB.V, resB.Za, resB.Zb, rA, rB, sa) {
			t.Errorf("n=%d: SM2CheckSa rejected", tc.n)
		}
		sa[0] ^= 1
		if SM2CheckSa(*resB.V, resB.Za, resB.Zb, rA, rB, sa) {
			t.Errorf("n=%d: SM2CheckSa accepted a modified value", tc.n)
		}
		sb[0] ^= 1
		if res := SM2GetSa(tc.n, pB, rB, pA, &dA, rA, &ra, idA, idB, sb); res.Success {
			t.Errorf("n=%d: SM2GetSa accepted a modified Sb", tc.n)
		}
	}
}

func TestSM2RejectsTampering(t *testing.T) {
	bad := []byte(gbtCiphertext)
	// Flip one bit in C3 and one in C2.
	for _, pos := range []int{131, len(bad) - 1} {
		mod := append([]byte(nil), bad...)
		if mod[pos] == '0' {
			mod[pos] = '1'
		} else {
			mod[pos] = '0'
		}
		if _, err := SM2Decrypt(string(mod), gbtPrivateKey); err == nil ||
			err.Error() != "decryption verification failed" {
			t.Errorf("pos %d: err = %v", pos, err)
		}
	}
	if _, err := SM2Decrypt("00", gbtPrivateKey); err == nil || err.Error() != "ciphertext too short" {
		t.Errorf("short ciphertext: %v", err)
	}
	if _, err := SM2Encrypt("", "00"); err == nil || err.Error() != "plaintext cannot be empty" {
		t.Errorf("empty plaintext: %v", err)
	}

	d := BigInt256FromHex(gbtPrivateKey)
	pub := SM2GetPublicKey(&d).ToHexEncoded()
	sigParts := strings.Split(gbtSignature, "h")
	n := SM2_N.ToHexLower()
	for _, sig := range []string{
		"", "abc", gbtSignature + "h00",
		"0h" + sigParts[1], sigParts[0] + "h0",
		n + "h" + sigParts[1], sigParts[0] + "h" + n,
	} {
		if SM2Verify("1234567812345678", sig, "message digest", pub) {
			t.Errorf("accepted signature %q", sig)
		}
	}
	// Not on the curve.
	offCurve := "04" + strings.Repeat("11", 64)
	if SM2Verify("1234567812345678", gbtSignature, "message digest", offCurve) {
		t.Error("accepted off-curve public key")
	}
	if _, err := SM2Encrypt("x", offCurve); err == nil || err.Error() != "invalid public key" {
		t.Errorf("off-curve encrypt: %v", err)
	}
	if _, err := SM2Decrypt(offCurve+strings.Repeat("00", 40), gbtPrivateKey); err == nil ||
		err.Error() != "invalid C1 point" {
		t.Errorf("off-curve decrypt: %v", err)
	}
}

// Only the low 32 bits of the bit length enter the padding. Fixing this would change
// outputs for messages of 512 MiB or more, so the existing behavior is pinned here.
func TestSM3LengthFieldTruncation(t *testing.T) {
	h := NewSM3()
	h.dataBitsLen = 1<<32 + 24 // as if 2^29 + 3 bytes had been hashed before this point
	h.buffLen = 3
	copy(h.buff[:], "abc")
	h.Finish()
	want := NewSM3()
	want.Update([]byte("abc"))
	want.Finish()
	if h.HashHexUpper() != want.HashHexUpper() {
		t.Errorf("high length bits changed the padding: %s", h.HashHexUpper())
	}
}

func TestConcurrentUse(t *testing.T) {
	d := BigInt256FromHex(gbtPrivateKey)
	pub := SM2GetPublicKey(&d)
	pubHex := pub.ToHexEncoded()
	s := NewSM4()
	s.SetKey([]byte("0123456789abcdef"), []byte("fedcba9876543210"))
	done := make(chan error, 8)
	for i := 0; i < cap(done); i++ {
		go func() {
			done <- func() error {
				sig, err := SM2Sign("id", "message", gbtPrivateKey)
				if err != nil {
					return err
				}
				if !SM2Verify("id", sig, "message", pubHex) {
					return errors.New("verify failed")
				}
				ct, err := SM2Encrypt("secret", pubHex)
				if err != nil {
					return err
				}
				if got, err := SM2Decrypt(ct, gbtPrivateKey); err != nil || got != "secret" {
					return fmt.Errorf("decrypt: %q, %v", got, err)
				}
				sct, err := s.Encrypt(strings.Repeat("x", 300))
				if err != nil {
					return err
				}
				if got, err := s.Decrypt(sct); err != nil || got != strings.Repeat("x", 300) {
					return fmt.Errorf("SM4: %v", err)
				}
				return nil
			}()
		}()
	}
	for i := 0; i < cap(done); i++ {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
}

// The hot paths stay free of heap allocations.
func TestNoAllocations(t *testing.T) {
	data := benchData(4096)
	if n := testing.AllocsPerRun(100, func() {
		var h SM3
		h.v = sm3IV
		h.Update(data)
		var out [32]byte
		h.sum(&out)
		sinkHash = out
	}); n != 0 {
		t.Errorf("SM3: %v allocations", n)
	}
	d := BigInt256FromHex(gbtPrivateKey)
	pub := SM2GetPublicKey(&d).ToHexEncoded()
	if n := testing.AllocsPerRun(20, func() {
		sinkBool = SM2Verify("1234567812345678", gbtSignature, "message digest", pub)
	}); n != 0 {
		t.Errorf("SM2Verify: %v allocations", n)
	}
}
