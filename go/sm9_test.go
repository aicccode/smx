package smx

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type sm9Vectors struct {
	Params struct {
		Q, N, T string
		P1      string `json:"P1"`
		P2      string `json:"P2"`
	} `json:"params"`
	Standard struct {
		Sign struct {
			MasterPrivate string `json:"master_private_key"`
			MasterPublic  string `json:"master_public_key"`
			UserID        string `json:"user_id"`
			HID           byte   `json:"hid"`
			UserPrivate   string `json:"user_private_key"`
			Message       string `json:"message"`
			R             string `json:"r"`
			PairingG      string `json:"pairing_g"`
			Signature     string `json:"signature"`
		} `json:"sign"`
		Exchange struct {
			MasterPrivate string `json:"master_private_key"`
			MasterPublic  string `json:"master_public_key"`
			HID           byte   `json:"hid"`
			sm9ExchangeVector
		} `json:"exchange"`
		Encapsulate struct {
			MasterPrivate string `json:"master_private_key"`
			MasterPublic  string `json:"master_public_key"`
			HID           byte   `json:"hid"`
			sm9KEMVector
		} `json:"encapsulate"`
		Encrypt struct {
			MasterPrivate    string `json:"master_private_key"`
			MasterPublic     string `json:"master_public_key"`
			UserID           string `json:"user_id"`
			HID              byte   `json:"hid"`
			UserPrivate      string `json:"user_private_key"`
			Plaintext        string `json:"plaintext"`
			R                string `json:"r"`
			CiphertextStream string `json:"ciphertext_stream"`
			CiphertextSM4    string `json:"ciphertext_sm4"`
		} `json:"encrypt"`
	} `json:"standard"`
	Extra struct {
		SignMasterPrivate string `json:"sign_master_private_key"`
		SignMasterPublic  string `json:"sign_master_public_key"`
		EncMasterPrivate  string `json:"enc_master_private_key"`
		EncMasterPublic   string `json:"enc_master_public_key"`
		Sign              []struct {
			UserID      string `json:"user_id"`
			UserPrivate string `json:"user_private_key"`
			MessageHex  string `json:"message_hex"`
			R           string `json:"r"`
			Signature   string `json:"signature"`
		} `json:"sign"`
		Encrypt []struct {
			UserID           string `json:"user_id"`
			UserPrivate      string `json:"user_private_key"`
			PlaintextHex     string `json:"plaintext_hex"`
			R                string `json:"r"`
			CiphertextStream string `json:"ciphertext_stream"`
			CiphertextSM4    string `json:"ciphertext_sm4"`
		} `json:"encrypt"`
		Encapsulate []sm9KEMVector      `json:"encapsulate"`
		Exchange    []sm9ExchangeVector `json:"exchange"`
	} `json:"extra"`
	InvalidPoints struct {
		G1 []sm9NamedValue `json:"g1"`
		G2 []sm9NamedValue `json:"g2"`
	} `json:"invalid_points"`
	InvalidScalars []sm9NamedValue `json:"invalid_scalars"`
	MaxMaster      string          `json:"max_valid_master_private_key"`
}

type sm9NamedValue struct{ Name, Value string }

type sm9KEMVector struct {
	UserID      string `json:"user_id"`
	UserPrivate string `json:"user_private_key"`
	KeyLen      int    `json:"key_len"`
	R           string `json:"r"`
	Ciphertext  string `json:"ciphertext"`
	Key         string `json:"key"`
}

type sm9ExchangeVector struct {
	IDA          string `json:"id_a"`
	IDB          string `json:"id_b"`
	UserPrivateA string `json:"user_private_key_a"`
	UserPrivateB string `json:"user_private_key_b"`
	KeyLen       int    `json:"key_len"`
	RandA        string `json:"r_a"`
	RandB        string `json:"r_b"`
	RA           string `json:"R_a"`
	RB           string `json:"R_b"`
	SharedKey    string `json:"shared_key"`
	SB           string `json:"s_b"`
	SA           string `json:"s_a"`
}

var sm9VectorsCache *sm9Vectors

func loadSM9Vectors(t testing.TB) *sm9Vectors {
	t.Helper()
	if sm9VectorsCache != nil {
		return sm9VectorsCache
	}
	data, err := os.ReadFile("../testvectors/sm9-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	v := new(sm9Vectors)
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
	if len(v.Extra.Sign) == 0 || len(v.Extra.Exchange) == 0 || len(v.InvalidPoints.G2) == 0 {
		t.Fatal("vector file did not decode")
	}
	sm9VectorsCache = v
	return v
}

func mustScalar(t testing.TB, s string) [4]uint64 {
	t.Helper()
	k, ok := sm9ParseScalar(s)
	if !ok {
		t.Fatalf("bad scalar %s", s)
	}
	return k
}

func mustG1(t testing.TB, s string) sm9G1Aff {
	t.Helper()
	p, ok := sm9ParseG1(s, false)
	if !ok {
		t.Fatalf("bad G1 point %s", s)
	}
	return p
}

func mustG2(t testing.TB, s string) sm9G2Aff {
	t.Helper()
	p, ok := sm9ParseG2(s)
	if !ok {
		t.Fatalf("bad G2 point %s", s)
	}
	return p
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// checkSignVector derives the user key, signs with the fixed r and verifies.
func checkSignVector(t *testing.T, masterPriv, masterPub, userID string, hid byte, userPriv string, msg []byte, r, want string) {
	t.Helper()
	if got, err := SM9SignMasterPublicKey(masterPriv); err != nil || got != masterPub {
		t.Errorf("master public key: %s %v", got, err)
	}
	if got, err := SM9GenerateSignUserKey(masterPriv, userID, hid); err != nil || got != userPriv {
		t.Errorf("user key for %q: %s %v", userID, got, err)
	}
	ds, ppub, rk := mustG1(t, userPriv), mustG2(t, masterPub), mustScalar(t, r)
	g := sm9Pair(&sm9P1, &ppub)
	if m, ok := sm9SignMasterFor(masterPub); !ok || m.g != g {
		t.Error("cached e(P1, Ppub-s) differs")
	}
	sig, ok := sm9SignWithRandom(msg, &ds, &g, &rk)
	if !ok || sig != want {
		t.Errorf("signature for %q:\n got %s\nwant %s", userID, sig, want)
	}
	if !SM9Verify(msg, want, userID, masterPub, hid) {
		t.Errorf("vector signature for %q does not verify", userID)
	}
	if SM9Verify(append(msg, 0), want, userID, masterPub, hid) {
		t.Error("signature verifies for a different message")
	}
}

func TestSM9StandardSign(t *testing.T) {
	v := loadSM9Vectors(t).Standard.Sign
	ppub := mustG2(t, v.MasterPublic)
	g := sm9Pair(&sm9P1, &ppub)
	if got := hex.EncodeToString(sm9GTBytes(&g)); got != v.PairingG {
		t.Errorf("e(P1, Ppub-s) = %s", got)
	}
	checkSignVector(t, v.MasterPrivate, v.MasterPublic, v.UserID, v.HID, v.UserPrivate, []byte(v.Message), v.R, v.Signature)
}

func TestSM9ExtraSign(t *testing.T) {
	v := loadSM9Vectors(t).Extra
	for _, tc := range v.Sign {
		checkSignVector(t, v.SignMasterPrivate, v.SignMasterPublic, tc.UserID, SM9HIDSign, tc.UserPrivate,
			mustHex(t, tc.MessageHex), tc.R, tc.Signature)
	}
}

func checkKEMVector(t *testing.T, masterPriv, masterPub string, hid byte, tc sm9KEMVector) {
	t.Helper()
	if got, err := SM9EncryptMasterPublicKey(masterPriv); err != nil || got != masterPub {
		t.Errorf("master public key: %s %v", got, err)
	}
	if got, err := SM9GenerateEncryptUserKey(masterPriv, tc.UserID, hid); err != nil || got != tc.UserPrivate {
		t.Errorf("user key for %q: %s %v", tc.UserID, got, err)
	}
	master, q, err := sm9EncSetup(tc.UserID, masterPub, hid)
	if err != nil {
		t.Fatal(err)
	}
	r := mustScalar(t, tc.R)
	k, c, ok := sm9EncapsulateWithRandom([]byte(tc.UserID), master, &q, tc.KeyLen, &r)
	if !ok || hex.EncodeToString(k) != tc.Key || hex.EncodeToString(c[:]) != tc.Ciphertext {
		t.Errorf("encapsulate for %q: key %x C %x", tc.UserID, k, c)
	}
	if got, err := SM9Decapsulate(tc.Ciphertext, tc.UserID, tc.UserPrivate, tc.KeyLen); err != nil || got != tc.Key {
		t.Errorf("decapsulate for %q: %s %v", tc.UserID, got, err)
	}
}

func TestSM9StandardEncapsulate(t *testing.T) {
	v := loadSM9Vectors(t).Standard.Encapsulate
	checkKEMVector(t, v.MasterPrivate, v.MasterPublic, v.HID, v.sm9KEMVector)
}

func TestSM9ExtraEncapsulate(t *testing.T) {
	v := loadSM9Vectors(t).Extra
	for _, tc := range v.Encapsulate {
		checkKEMVector(t, v.EncMasterPrivate, v.EncMasterPublic, SM9HIDEncrypt, tc)
	}
}

func checkEncryptVector(t *testing.T, masterPriv, masterPub, userID string, hid byte, userPriv string, msg []byte, r, wantStream, wantSM4 string) {
	t.Helper()
	if got, err := SM9GenerateEncryptUserKey(masterPriv, userID, hid); err != nil || got != userPriv {
		t.Errorf("user key for %q: %s %v", userID, got, err)
	}
	master, q, err := sm9EncSetup(userID, masterPub, hid)
	if err != nil {
		t.Fatal(err)
	}
	rk := mustScalar(t, r)
	for _, m := range []struct {
		mode SM9EncryptMode
		want string
	}{{SM9ModeStream, wantStream}, {SM9ModeSM4, wantSM4}} {
		ct, ok := sm9EncryptWithRandom(msg, []byte(userID), master, &q, &rk, m.mode)
		if !ok || ct != m.want {
			t.Errorf("encrypt for %q mode %d:\n got %s\nwant %s", userID, m.mode, ct, m.want)
		}
		pt, err := SM9Decrypt(m.want, userID, userPriv, m.mode)
		if err != nil || string(pt) != string(msg) {
			t.Errorf("decrypt for %q mode %d: %x %v", userID, m.mode, pt, err)
		}
		// With a 16-byte C2 both modes derive the same K2, so the MAC check passes and
		// the stream mode returns garbage; it must never return the plaintext.
		other := SM9ModeSM4 - m.mode
		if pt, err := SM9Decrypt(m.want, userID, userPriv, other); err == nil && string(pt) == string(msg) {
			t.Errorf("decrypt in the wrong mode recovered the plaintext for %q", userID)
		}
	}
}

func TestSM9StandardEncrypt(t *testing.T) {
	v := loadSM9Vectors(t).Standard.Encrypt
	checkEncryptVector(t, v.MasterPrivate, v.MasterPublic, v.UserID, v.HID, v.UserPrivate, []byte(v.Plaintext),
		v.R, v.CiphertextStream, v.CiphertextSM4)
}

func TestSM9ExtraEncrypt(t *testing.T) {
	v := loadSM9Vectors(t).Extra
	for _, tc := range v.Encrypt {
		checkEncryptVector(t, v.EncMasterPrivate, v.EncMasterPublic, tc.UserID, SM9HIDEncrypt, tc.UserPrivate,
			mustHex(t, tc.PlaintextHex), tc.R, tc.CiphertextStream, tc.CiphertextSM4)
	}
}

func checkExchangeVector(t *testing.T, masterPriv, masterPub string, hid byte, tc sm9ExchangeVector) {
	t.Helper()
	for _, u := range []struct{ id, want string }{{tc.IDA, tc.UserPrivateA}, {tc.IDB, tc.UserPrivateB}} {
		if got, err := SM9GenerateEncryptUserKey(masterPriv, u.id, hid); err != nil || got != u.want {
			t.Errorf("user key for %q: %s %v", u.id, got, err)
		}
	}
	_, qB, err := sm9EncSetup(tc.IDB, masterPub, hid)
	if err != nil {
		t.Fatal(err)
	}
	_, qA, err := sm9EncSetup(tc.IDA, masterPub, hid)
	if err != nil {
		t.Fatal(err)
	}
	ra, rb := mustScalar(t, tc.RandA), mustScalar(t, tc.RandB)
	if got, ok := sm9ExchangeInitWithRandom(&qB, &ra); !ok || got != tc.RA {
		t.Errorf("R_A = %s", got)
	}
	if got, ok := sm9ExchangeInitWithRandom(&qA, &rb); !ok || got != tc.RB {
		t.Errorf("R_B = %s", got)
	}
	resB := SM9ExchangeRespond(tc.KeyLen, tc.IDA, tc.IDB, masterPub, tc.UserPrivateB, tc.RandB, tc.RB, tc.RA)
	if !resB.Success || resB.SharedKey != tc.SharedKey || resB.SB != tc.SB || resB.S2 != tc.SA {
		t.Errorf("respond: %+v key %s SB %s S2 %s", resB, resB.SharedKey, resB.SB, resB.S2)
	}
	resA := SM9ExchangeConfirm(tc.KeyLen, tc.IDA, tc.IDB, masterPub, tc.UserPrivateA, tc.RandA, tc.RA, tc.RB, tc.SB)
	if !resA.Success || resA.SharedKey != tc.SharedKey || resA.SA != tc.SA {
		t.Errorf("confirm: %v key %s SA %s", resA, resA.SharedKey, resA.SA)
	}
	if !SM9ExchangeCheck(resB.S2, resA.SA) {
		t.Error("check failed")
	}
}

func TestSM9StandardExchange(t *testing.T) {
	v := loadSM9Vectors(t).Standard.Exchange
	checkExchangeVector(t, v.MasterPrivate, v.MasterPublic, v.HID, v.sm9ExchangeVector)
}

func TestSM9ExtraExchange(t *testing.T) {
	v := loadSM9Vectors(t).Extra
	for _, tc := range v.Exchange {
		checkExchangeVector(t, v.EncMasterPrivate, v.EncMasterPublic, SM9HIDExchange, tc)
	}
}
