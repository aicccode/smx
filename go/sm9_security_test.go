package smx

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
)

// sm9Keys is a full set of freshly generated keys.
type sm9Keys struct {
	signPriv, signPub, encPriv, encPub string
}

func newSM9Keys(t testing.TB) sm9Keys {
	t.Helper()
	var k sm9Keys
	var err error
	if k.signPriv, k.signPub, err = SM9GenerateSignMasterKey(); err != nil {
		t.Fatal(err)
	}
	if k.encPriv, k.encPub, err = SM9GenerateEncryptMasterKey(); err != nil {
		t.Fatal(err)
	}
	return k
}

// mustOK returns a function that unwraps (string, error) results, failing t on error.
func mustOK(t testing.TB) func(string, error) string {
	return func(s string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
}

func TestSM9RoundTrips(t *testing.T) {
	k := newSM9Keys(t)
	if pub := mustOK(t)(SM9SignMasterPublicKey(k.signPriv)); pub != k.signPub {
		t.Fatal("sign master public key mismatch")
	}
	if pub := mustOK(t)(SM9EncryptMasterPublicKey(strings.ToUpper(k.encPriv))); pub != k.encPub {
		t.Fatal("encrypt master public key mismatch (uppercase private key)")
	}
	ids := []string{"", "alice", "张三@example.com", strings.Repeat("x", 1000)}
	for _, id := range ids {
		ds := mustOK(t)(SM9GenerateSignUserKey(k.signPriv, id, SM9HIDSign))
		for _, msg := range [][]byte{nil, {0}, []byte("message"), benchData(5000)} {
			sig := mustOK(t)(SM9Sign(msg, ds, k.signPub))
			if len(sig) != sm9SignatureHexLen || sig != strings.ToLower(sig) {
				t.Fatal("signature format")
			}
			if !SM9Verify(msg, sig, id, k.signPub, SM9HIDSign) {
				t.Fatalf("signature by %q does not verify", id)
			}
			if !SM9Verify(msg, sig, id, strings.ToUpper(k.signPub), SM9HIDSign) {
				t.Fatal("uppercase master public key rejected")
			}
			if SM9Verify(msg, sig, id+"!", k.signPub, SM9HIDSign) || SM9Verify(msg, sig, id, k.signPub, 0x02) {
				t.Fatal("signature verifies for another ID or hid")
			}
			if SM9Verify(append([]byte{1}, msg...), sig, id, k.signPub, SM9HIDSign) {
				t.Fatal("signature verifies for another message")
			}
		}
		if _, err := SM9Sign([]byte("m"), strings.ToUpper(ds), strings.ToUpper(k.signPub)); err != nil {
			t.Fatal("uppercase keys rejected by Sign")
		}

		de := mustOK(t)(SM9GenerateEncryptUserKey(k.encPriv, id, SM9HIDEncrypt))
		for _, n := range []int{1, 15, 16, 17, 32, 100, 4096} {
			msg := benchData(n)
			for _, mode := range []SM9EncryptMode{SM9ModeStream, SM9ModeSM4} {
				ct := mustOK(t)(SM9Encrypt(msg, id, k.encPub, SM9HIDEncrypt, mode))
				pt, err := SM9Decrypt(ct, id, de, mode)
				if err != nil || !bytes.Equal(pt, msg) {
					t.Fatalf("decrypt %d bytes mode %d for %q: %v", n, mode, id, err)
				}
				if _, err := SM9Decrypt(ct, id, strings.ToUpper(de), mode); err != nil {
					t.Fatal("uppercase user key rejected by Decrypt")
				}
				if _, err := SM9Decrypt(ct, id+"!", de, mode); err == nil {
					t.Fatal("decrypted with another ID")
				}
			}
		}
		for _, klen := range []int{1, 16, 32, 33, 1000} {
			key, c, err := SM9Encapsulate(id, k.encPub, klen, SM9HIDEncrypt)
			if err != nil || len(key) != 2*klen {
				t.Fatal(err)
			}
			if got, err := SM9Decapsulate(c, id, de, klen); err != nil || got != key {
				t.Fatalf("decapsulate: %v", err)
			}
			if got, err := SM9Decapsulate(c, id+"!", de, klen); err == nil && got == key {
				t.Fatal("decapsulated with another ID")
			}
		}
	}
}

func TestSM9ExchangeRoundTrip(t *testing.T) {
	k := newSM9Keys(t)
	idA, idB := "alice", "bob"
	deA := mustOK(t)(SM9GenerateEncryptUserKey(k.encPriv, idA, SM9HIDExchange))
	deB := mustOK(t)(SM9GenerateEncryptUserKey(k.encPriv, idB, SM9HIDExchange))
	for _, klen := range []int{1, 16, 64, 1 << 20} {
		rA, RA, err := SM9ExchangeInit(idB, k.encPub, SM9HIDExchange)
		if err != nil {
			t.Fatal(err)
		}
		rB, RB, err := SM9ExchangeInit(idA, k.encPub, SM9HIDExchange)
		if err != nil {
			t.Fatal(err)
		}
		resB := SM9ExchangeRespond(klen, idA, idB, k.encPub, deB, rB, RB, RA)
		if !resB.Success {
			t.Fatal(resB.Message)
		}
		resA := SM9ExchangeConfirm(klen, idA, idB, k.encPub, deA, rA, RA, RB, resB.SB)
		if !resA.Success || resA.SharedKey != resB.SharedKey || len(resA.SharedKey) != 2*klen {
			t.Fatalf("keys differ: %v", resA)
		}
		if !SM9ExchangeCheck(resB.S2, resA.SA) {
			t.Fatal("S_A rejected")
		}
		if klen != 16 {
			continue
		}

		// Mismatches.
		flipped := flipHex(resB.SB, 10)
		if r := SM9ExchangeConfirm(klen, idA, idB, k.encPub, deA, rA, RA, RB, flipped); r.Success || r.SharedKey != "" {
			t.Fatal("A accepted a wrong S_B")
		}
		if SM9ExchangeCheck(resB.S2, flipHex(resA.SA, 0)) || SM9ExchangeCheck(resB.S2, strings.ToUpper(resA.SA)) ||
			SM9ExchangeCheck(resB.S2, resA.SA[:62]) {
			t.Fatal("B accepted a wrong S_A")
		}
		// A with the wrong peer identity disagrees with B.
		if r := SM9ExchangeConfirm(klen, idA, "mallory", k.encPub, deA, rA, RA, RB, resB.SB); r.Success {
			t.Fatal("confirm succeeded with a different responder ID")
		}
		// A key for another identity cannot complete the exchange.
		deC := mustOK(t)(SM9GenerateEncryptUserKey(k.encPriv, "carol", SM9HIDExchange))
		if r := SM9ExchangeConfirm(klen, idA, idB, k.encPub, deC, rA, RA, RB, resB.SB); r.Success {
			t.Fatal("confirm succeeded with another user's key")
		}
		// Bad inputs.
		for name, r := range map[string]SM9KeyExchangeResult{
			"keylen0":    SM9ExchangeRespond(0, idA, idB, k.encPub, deB, rB, RB, RA),
			"keylenMax":  SM9ExchangeRespond(1<<20+1, idA, idB, k.encPub, deB, rB, RB, RA),
			"badRA":      SM9ExchangeRespond(klen, idA, idB, k.encPub, deB, rB, RB, flipHex(RA, 100)),
			"badRB":      SM9ExchangeRespond(klen, idA, idB, k.encPub, deB, rB, RA[:128], RA),
			"badKey":     SM9ExchangeRespond(klen, idA, idB, k.encPub, deB[:200], rB, RB, RA),
			"badR":       SM9ExchangeRespond(klen, idA, idB, k.encPub, deB, strings.Repeat("0", 64), RB, RA),
			"badMaster":  SM9ExchangeRespond(klen, idA, idB, k.signPub, deB, rB, RB, RA),
			"badSBUpper": SM9ExchangeConfirm(klen, idA, idB, k.encPub, deA, rA, RA, RB, strings.ToUpper(resB.SB)),
		} {
			if r.Success || r.Message == "" || r.SharedKey != "" {
				t.Errorf("%s: %+v", name, r.Message)
			}
		}
	}
}

// flipHex changes the hex digit at i to a different lowercase digit.
func flipHex(s string, i int) string {
	b := []byte(s)
	if b[i] == '0' {
		b[i] = '1'
	} else {
		b[i] = '0'
	}
	return string(b)
}

func TestSM9Tamper(t *testing.T) {
	v := loadSM9Vectors(t).Standard
	sig := v.Sign.Signature
	msg := []byte(v.Sign.Message)
	for i := 0; i < len(sig); i += 7 {
		if SM9Verify(msg, flipHex(sig, i), v.Sign.UserID, v.Sign.MasterPublic, v.Sign.HID) {
			t.Fatalf("tampered signature (digit %d) verifies", i)
		}
	}
	for _, bad := range []string{"", sig[:len(sig)-2], sig + "00", strings.ToUpper(sig),
		strings.Repeat("0", 64) + sig[64:], v.Sign.MasterPublic[:64] + sig[64:]} {
		if SM9Verify(msg, bad, v.Sign.UserID, v.Sign.MasterPublic, v.Sign.HID) {
			t.Fatalf("malformed signature verifies: %.20s", bad)
		}
	}
	// h = N must be rejected, as must h + N style aliases.
	nHex := fmt.Sprintf("%064x", limbsToBig(sm9N))
	if SM9Verify(msg, nHex+sig[64:], v.Sign.UserID, v.Sign.MasterPublic, v.Sign.HID) {
		t.Fatal("h = N accepted")
	}

	e := v.Encrypt
	for _, m := range []struct {
		mode SM9EncryptMode
		ct   string
	}{{SM9ModeStream, e.CiphertextStream}, {SM9ModeSM4, e.CiphertextSM4}} {
		for i := 0; i < len(m.ct); i += 5 {
			if _, err := SM9Decrypt(flipHex(m.ct, i), e.UserID, e.UserPrivate, m.mode); err != errSM9Decrypt {
				t.Fatalf("tampered ciphertext (digit %d): %v", i, err)
			}
		}
		for _, bad := range []string{"", m.ct[:2*97], m.ct[:len(m.ct)-1], m.ct[:len(m.ct)-2], m.ct + "00",
			strings.ToUpper(m.ct), "1" + m.ct[1:]} {
			if _, err := SM9Decrypt(bad, e.UserID, e.UserPrivate, m.mode); err != errSM9Decrypt {
				t.Fatalf("malformed ciphertext: %v", err)
			}
		}
		if _, err := SM9Decrypt(m.ct, e.UserID, e.UserPrivate, SM9EncryptMode(7)); err != errSM9Mode {
			t.Fatal("invalid mode accepted")
		}
	}

	k := v.Encapsulate
	if _, err := SM9Decapsulate(strings.ToUpper(k.Ciphertext), k.UserID, k.UserPrivate, k.KeyLen); err == nil {
		t.Fatal("uppercase encapsulation accepted")
	}
	if got, _ := SM9Decapsulate(k.Ciphertext, k.UserID, k.UserPrivate, k.KeyLen+1); got[:2*k.KeyLen] != k.Key {
		t.Fatal("KDF prefix property")
	}
}

func TestSM9InvalidInputs(t *testing.T) {
	v := loadSM9Vectors(t)
	std := v.Standard
	sig := std.Sign
	msg := []byte(sig.Message)
	for _, p := range v.InvalidPoints.G1 {
		if _, ok := sm9ParseG1(p.Value, false); ok {
			t.Errorf("G1 %s accepted", p.Name)
		}
		if _, err := SM9Sign(msg, p.Value, sig.MasterPublic); err == nil {
			t.Errorf("Sign accepted user key %s", p.Name)
		}
		if _, err := SM9Encrypt(msg, "Bob", p.Value, SM9HIDEncrypt, SM9ModeStream); err == nil {
			t.Errorf("Encrypt accepted master key %s", p.Name)
		}
		if _, _, err := SM9Encapsulate("Bob", p.Value, 16, SM9HIDEncrypt); err == nil {
			t.Errorf("Encapsulate accepted master key %s", p.Name)
		}
		if _, _, err := SM9ExchangeInit("Bob", p.Value, SM9HIDExchange); err == nil {
			t.Errorf("ExchangeInit accepted master key %s", p.Name)
		}
		if _, err := SM9Decapsulate(p.Value, "Bob", std.Encapsulate.UserPrivate, 32); err == nil {
			t.Errorf("Decapsulate accepted C %s", p.Name)
		}
		ct := std.Encrypt.CiphertextStream
		if _, err := SM9Decrypt(p.Value+ct[130:], "Bob", std.Encrypt.UserPrivate, SM9ModeStream); err == nil {
			t.Errorf("Decrypt accepted C1 %s", p.Name)
		}
		if len(p.Value) == 130 && SM9Verify(msg, sig.Signature[:64]+p.Value, sig.UserID, sig.MasterPublic, sig.HID) {
			t.Errorf("Verify accepted S %s", p.Name)
		}
		x := std.Exchange
		if r := SM9ExchangeRespond(16, x.IDA, x.IDB, x.MasterPublic, x.UserPrivateB, x.RandB, x.RB, p.Value); r.Success {
			t.Errorf("Respond accepted R_A %s", p.Name)
		}
		if r := SM9ExchangeConfirm(16, x.IDA, x.IDB, x.MasterPublic, x.UserPrivateA, x.RandA, x.RA, p.Value, x.SB); r.Success {
			t.Errorf("Confirm accepted R_B %s", p.Name)
		}
	}
	for _, p := range v.InvalidPoints.G2 {
		if _, ok := sm9ParseG2(p.Value); ok {
			t.Errorf("G2 %s accepted", p.Name)
		}
		if _, err := SM9Sign(msg, sig.UserPrivate, p.Value); err == nil {
			t.Errorf("Sign accepted master key %s", p.Name)
		}
		if SM9Verify(msg, sig.Signature, sig.UserID, p.Value, sig.HID) {
			t.Errorf("Verify accepted master key %s", p.Name)
		}
		e := std.Encrypt
		if _, err := SM9Decrypt(e.CiphertextStream, e.UserID, p.Value, SM9ModeStream); err == nil {
			t.Errorf("Decrypt accepted user key %s", p.Name)
		}
		if _, err := SM9Decapsulate(std.Encapsulate.Ciphertext, "Bob", p.Value, 32); err == nil {
			t.Errorf("Decapsulate accepted user key %s", p.Name)
		}
		x := std.Exchange
		if r := SM9ExchangeRespond(16, x.IDA, x.IDB, x.MasterPublic, p.Value, x.RandB, x.RB, x.RA); r.Success {
			t.Errorf("Respond accepted user key %s", p.Name)
		}
	}
	for _, s := range v.InvalidScalars {
		if _, err := SM9SignMasterPublicKey(s.Value); err == nil {
			t.Errorf("sign master key %s accepted", s.Name)
		}
		if _, err := SM9EncryptMasterPublicKey(s.Value); err == nil {
			t.Errorf("encrypt master key %s accepted", s.Name)
		}
		if _, err := SM9GenerateSignUserKey(s.Value, "a", SM9HIDSign); err == nil {
			t.Errorf("GenerateSignUserKey accepted %s", s.Name)
		}
		if _, err := SM9GenerateEncryptUserKey(s.Value, "a", SM9HIDEncrypt); err == nil {
			t.Errorf("GenerateEncryptUserKey accepted %s", s.Name)
		}
		x := std.Exchange
		if r := SM9ExchangeRespond(16, x.IDA, x.IDB, x.MasterPublic, x.UserPrivateB, s.Value, x.RB, x.RA); r.Success {
			t.Errorf("Respond accepted r %s", s.Name)
		}
	}
	for _, s := range []string{v.MaxMaster, strings.ToUpper(v.MaxMaster)} {
		if _, err := SM9SignMasterPublicKey(s); err != nil {
			t.Error("max master key rejected")
		}
		if _, err := SM9GenerateEncryptUserKey(s, "a", SM9HIDEncrypt); err != nil {
			t.Error("max master key rejected for user keys")
		}
	}

	e := std.Encrypt
	if _, err := SM9Encrypt(nil, e.UserID, e.MasterPublic, SM9HIDEncrypt, SM9ModeStream); err != errSM9EmptyText {
		t.Error("empty plaintext accepted (stream)")
	}
	if _, err := SM9Encrypt([]byte{}, e.UserID, e.MasterPublic, SM9HIDEncrypt, SM9ModeSM4); err != errSM9EmptyText {
		t.Error("empty plaintext accepted (SM4)")
	}
	if _, err := SM9Encrypt([]byte("m"), e.UserID, e.MasterPublic, SM9HIDEncrypt, -1); err != errSM9Mode {
		t.Error("invalid mode accepted")
	}
	if _, _, err := SM9Encapsulate("Bob", e.MasterPublic, 0, SM9HIDEncrypt); err != errSM9InvalidKeyLen {
		t.Error("key length 0 accepted")
	}
	if _, err := SM9Decapsulate(std.Encapsulate.Ciphertext, "Bob", std.Encapsulate.UserPrivate, -1); err != errSM9InvalidKeyLen {
		t.Error("key length -1 accepted")
	}
	// The G2 point where a G1 key belongs and the reverse.
	if _, err := SM9Sign(msg, sig.MasterPublic, sig.MasterPublic); err == nil {
		t.Error("G2 point accepted as a signing user key")
	}
	if _, err := SM9Encrypt(msg, "Bob", sig.MasterPublic, SM9HIDEncrypt, SM9ModeStream); err == nil {
		t.Error("G2 point accepted as an encryption master key")
	}
}

// TestSM9UserKeyZero: a master key equal to N - H1(ID||hid) makes t1 zero.
func TestSM9UserKeyZero(t *testing.T) {
	h1 := sm9H1([]byte("alice"), SM9HIDSign)
	ks := new(big.Int).Sub(limbsToBig(sm9N), limbsToBig(h1))
	s := fmt.Sprintf("%064x", ks)
	if _, err := SM9GenerateSignUserKey(s, "alice", SM9HIDSign); err != errSM9InvalidUserKey {
		t.Fatalf("t1 = 0 accepted: %v", err)
	}
	if _, err := SM9GenerateEncryptUserKey(s, "alice", SM9HIDSign); err != errSM9InvalidUserKey {
		t.Fatal("t1 = 0 accepted for encryption")
	}
	if _, err := SM9GenerateSignUserKey(s, "alice", SM9HIDEncrypt); err != nil {
		t.Fatal("other hid rejected")
	}
	// For that master key, Q of "alice" is the identity: encryption to it is refused, and
	// a verification with P = O fails cleanly.
	encPub := mustOK(t)(SM9EncryptMasterPublicKey(s))
	if _, err := SM9Encrypt([]byte("m"), "alice", encPub, SM9HIDSign, SM9ModeStream); err == nil {
		t.Fatal("encryption to the identity point")
	}
	signPub := mustOK(t)(SM9SignMasterPublicKey(s))
	v := loadSM9Vectors(t).Standard.Sign
	if SM9Verify([]byte("m"), v.Signature, "alice", signPub, SM9HIDSign) {
		t.Fatal("verification with P = O succeeded")
	}
}

func TestSM9RandomFailure(t *testing.T) {
	v := loadSM9Vectors(t).Standard
	for name, r := range map[string]interface{ Read([]byte) (int, error) }{
		"error":    failingReader{errors.New("no entropy")},
		"short":    &shortReader{},
		"zeros":    constantReader(0),
		"all ones": constantReader(0xFF),
	} {
		t.Run(name, func(t *testing.T) {
			withRandReader(t, r, func() {
				if a, b, err := SM9GenerateSignMasterKey(); err != errRandom || a != "" || b != "" {
					t.Errorf("GenerateSignMasterKey: %v", err)
				}
				if _, _, err := SM9GenerateEncryptMasterKey(); err != errRandom {
					t.Errorf("GenerateEncryptMasterKey: %v", err)
				}
				if _, err := SM9Sign([]byte("m"), v.Sign.UserPrivate, v.Sign.MasterPublic); err != errRandom {
					t.Errorf("Sign: %v", err)
				}
				if _, err := SM9Encrypt([]byte("m"), "Bob", v.Encrypt.MasterPublic, SM9HIDEncrypt, SM9ModeStream); err != errRandom {
					t.Errorf("Encrypt: %v", err)
				}
				if _, _, err := SM9Encapsulate("Bob", v.Encrypt.MasterPublic, 16, SM9HIDEncrypt); err != errRandom {
					t.Errorf("Encapsulate: %v", err)
				}
				if _, _, err := SM9ExchangeInit("Bob", v.Exchange.MasterPublic, SM9HIDExchange); err != errRandom {
					t.Errorf("ExchangeInit: %v", err)
				}
			})
		})
	}
}

func TestSM9ResultRedaction(t *testing.T) {
	r := SM9KeyExchangeResult{Success: true, SharedKey: "deadbeefcafe", SB: "aa"}
	for _, s := range []string{fmt.Sprint(r), fmt.Sprintf("%+v", r), fmt.Sprintf("%#v", &r)} {
		if strings.Contains(s, "deadbeef") {
			t.Fatalf("shared key printed: %s", s)
		}
	}
	j, _ := json.Marshal(r)
	if strings.Contains(string(j), "deadbeef") {
		t.Fatal("shared key in JSON")
	}
	if err := gob.NewEncoder(new(bytes.Buffer)).Encode(r); err == nil {
		t.Fatal("gob encoded the shared key")
	}
}

// TestSM9Concurrent exercises the master key cache from many goroutines (run with -race).
func TestSM9Concurrent(t *testing.T) {
	v := loadSM9Vectors(t)
	std := v.Standard
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			msg := []byte(fmt.Sprint(i))
			s, err := SM9Sign(msg, std.Sign.UserPrivate, std.Sign.MasterPublic)
			if err != nil || !SM9Verify(msg, s, std.Sign.UserID, std.Sign.MasterPublic, std.Sign.HID) {
				t.Error("concurrent sign/verify")
			}
			ct, err := SM9Encrypt(msg, "Bob", std.Encrypt.MasterPublic, SM9HIDEncrypt, SM9ModeSM4)
			if pt, err2 := SM9Decrypt(ct, "Bob", std.Encrypt.UserPrivate, SM9ModeSM4); err != nil || err2 != nil || !bytes.Equal(pt, msg) {
				t.Error("concurrent encrypt/decrypt")
			}
		}(i)
	}
	wg.Wait()
	// Overflow the cache: it must keep working after being emptied.
	for i := 0; i < sm9CacheMax+3; i++ {
		k := [4]uint64{uint64(i + 1)}
		if _, ok := sm9EncMasterFor(sm9EncPublic(&k)); !ok {
			t.Fatal("cache insert")
		}
	}
	if _, err := SM9Encrypt([]byte("m"), "Bob", std.Encrypt.MasterPublic, SM9HIDEncrypt, SM9ModeStream); err != nil {
		t.Fatal(err)
	}
}
