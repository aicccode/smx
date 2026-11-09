package smx

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// SM9EncryptMode selects how SM9Encrypt turns the KDF output into C2. The ciphertext
// does not record it, so SM9Decrypt must be given the same mode.
type SM9EncryptMode int

const (
	// SM9ModeStream XORs the message with the KDF stream (the default of the standard).
	SM9ModeStream SM9EncryptMode = iota
	// SM9ModeSM4 encrypts the PKCS#7-padded message with SM4-ECB under a 16-byte KDF key,
	// as in the worked example of GB/T 38635.5. It uses the table-driven SM4 of this
	// branch, which is not cache-timing resistant; see the SM4 type.
	SM9ModeSM4
)

const (
	sm9MACKeyLen = 32
	sm9SM4KeyLen = 16
	sm9C3Len     = 32
	sm9C1Len     = 65
)

var (
	// errSM9Decrypt is the one error for every malformed or unauthentic ciphertext.
	errSM9Decrypt     = errors.New("sm9: decryption failed")
	errSM9Mode        = errors.New("sm9: invalid encryption mode")
	errSM9EmptyText   = errors.New("sm9: plaintext cannot be empty")
	errSM9Decapsulate = errors.New("sm9: decapsulation failed")
)

// sm9UserPublic returns Q = [H1(ID||hid)]P1 + Ppub-e, from public data only.
func sm9UserPublic(userID []byte, hid byte, ppub *sm9G1Aff) (sm9G1Aff, bool) {
	h1 := sm9H1(userID, hid)
	p1, pub := sm9P1.jac(), ppub.jac()
	var q sm9G1Jac
	sm9G1ScalarMultVar(&q, &p1, &h1)
	sm9G1AddVar(&q, &q, &pub)
	return q.toAffine()
}

// sm9EncSetup parses the encryption master public key and derives the user's Q.
func sm9EncSetup(userID, masterPublic string, hid byte) (*sm9EncMaster, sm9G1Aff, error) {
	master, ok := sm9EncMasterFor(masterPublic)
	if !ok {
		return nil, sm9G1Aff{}, errInvalidPublicKey
	}
	q, ok := sm9UserPublic(stringAsBytes(userID), hid, &master.ppub)
	if !ok {
		return nil, q, errInvalidPublicKey
	}
	return master, q, nil
}

// sm9EncapsulateWithRandom computes C = [r]Q and K = KDF(C.xy || e(Ppub-e, P2)^r || ID)
// and reports false if K is all zeros and r must be replaced.
func sm9EncapsulateWithRandom(userID []byte, master *sm9EncMaster, q *sm9G1Aff, klen int, r *[4]uint64) ([]byte, [65]byte, bool) {
	c, ok := sm9G1Mul(q, r)
	if !ok {
		return nil, [65]byte{}, false
	}
	var w sm9Fp12
	sm9GTExp(&w, &master.g, r)
	wb := sm9GTBytes(&w)
	cb := c.bytes()
	k := sm9KDF(klen, cb[1:], wb, userID)
	wipeBytes(wb)
	if sm9AllZero(k) {
		return nil, cb, false
	}
	return k, cb, true
}

func sm9KeyLenValid(klen int) bool {
	return klen >= 1 && uint64(klen) <= sm2MaxKDFBytes && klen <= math.MaxInt/2
}

// SM9Encapsulate generates a key of keyLen bytes for userID and its encapsulation, a G1
// point, returning (keyHex, ciphertextHex). hid is normally SM9HIDEncrypt.
func SM9Encapsulate(userID, masterPublic string, keyLen int, hid byte) (string, string, error) {
	if !sm9KeyLenValid(keyLen) {
		return "", "", errSM9InvalidKeyLen
	}
	master, q, err := sm9EncSetup(userID, masterPublic, hid)
	if err != nil {
		return "", "", err
	}
	for i := 0; i < sm2MaxAttempts; i++ {
		r, err := sm9RandomScalar()
		if err != nil {
			return "", "", err
		}
		k, c, ok := sm9EncapsulateWithRandom(stringAsBytes(userID), master, &q, keyLen, &r)
		wipeLimbs(&r)
		if ok {
			key := bytesToHex(k)
			wipeBytes(k)
			return key, bytesToHex(c[:]), nil
		}
	}
	return "", "", errRandom
}

// SM9Decapsulate recovers the key of keyLen bytes from the encapsulation (lowercase hex
// of a G1 point) with userID's encryption private key.
func SM9Decapsulate(ciphertext, userID, userPrivate string, keyLen int) (string, error) {
	if !sm9KeyLenValid(keyLen) {
		return "", errSM9InvalidKeyLen
	}
	c, ok := sm9ParseG1(ciphertext, true)
	if !ok {
		return "", errSM9Decapsulate
	}
	de, ok := sm9ParseG2(userPrivate)
	if !ok {
		return "", errInvalidPrivateKey
	}
	defer wipeG2(&de)
	w := sm9Pair(&c, &de)
	wb := sm9GTBytes(&w)
	cb := c.bytes()
	k := sm9KDF(keyLen, cb[1:], wb, stringAsBytes(userID))
	wipeBytes(wb)
	if sm9AllZero(k) {
		return "", errSM9Decapsulate
	}
	key := bytesToHex(k)
	wipeBytes(k)
	return key, nil
}

// sm9EncryptLenValid checks the KDF limit and that the hex ciphertext fits in an int.
func sm9EncryptLenValid(n int) bool {
	return uint64(n) <= sm2MaxKDFBytes-sm9MACKeyLen-sm4BlockSize &&
		n <= (math.MaxInt-2*(sm9C1Len+sm9C3Len+sm4BlockSize))/2
}

// SM9Encrypt encrypts plaintext for userID under the encryption master public key. The
// result is the lowercase hex of C1 || C3 || C2. hid is normally SM9HIDEncrypt.
func SM9Encrypt(plaintext []byte, userID, masterPublic string, hid byte, mode SM9EncryptMode) (string, error) {
	if mode != SM9ModeStream && mode != SM9ModeSM4 {
		return "", errSM9Mode
	}
	if len(plaintext) == 0 {
		return "", errSM9EmptyText
	}
	if !sm9EncryptLenValid(len(plaintext)) {
		return "", errPlaintextTooLong
	}
	master, q, err := sm9EncSetup(userID, masterPublic, hid)
	if err != nil {
		return "", err
	}
	for i := 0; i < sm2MaxAttempts; i++ {
		r, err := sm9RandomScalar()
		if err != nil {
			return "", err
		}
		ct, ok := sm9EncryptWithRandom(plaintext, stringAsBytes(userID), master, &q, &r, mode)
		wipeLimbs(&r)
		if ok {
			return ct, nil
		}
	}
	return "", errRandom
}

// sm9EncKeyLen returns the length of K1 for a C2 or message of n bytes.
func sm9EncKeyLen(n int, mode SM9EncryptMode) int {
	if mode == SM9ModeSM4 {
		return sm9SM4KeyLen
	}
	return n
}

// sm9EncryptWithRandom encrypts with the random r and reports false if K1 is all zeros
// and r must be replaced.
func sm9EncryptWithRandom(msg, userID []byte, master *sm9EncMaster, q *sm9G1Aff, r *[4]uint64, mode SM9EncryptMode) (string, bool) {
	k1Len := sm9EncKeyLen(len(msg), mode)
	k, c1, ok := sm9EncapsulateWithRandom(userID, master, q, k1Len+sm9MACKeyLen, r)
	if k == nil {
		return "", false
	}
	defer wipeBytes(k)
	k1, k2 := k[:k1Len], k[k1Len:]
	if !ok || sm9AllZero(k1) {
		return "", false
	}

	var c2 []byte
	if mode == SM9ModeSM4 {
		size, _ := sm4PaddedSize(len(msg))
		c2 = make([]byte, size)
		copy(c2, msg)
		for i := len(msg); i < size; i++ {
			c2[i] = byte(size - len(msg))
		}
		sm9SM4ECB(k1, c2, false)
	} else {
		c2 = make([]byte, len(msg))
		subtle.XORBytes(c2, msg, k1)
	}
	c3 := sm9MAC(k2, c2)

	out := make([]byte, 2*(sm9C1Len+sm9C3Len+len(c2)))
	encodeHexTo(out, c1[:], lowerHex)
	encodeHexTo(out[2*sm9C1Len:], c3[:], lowerHex)
	encodeHexTo(out[2*(sm9C1Len+sm9C3Len):], c2, lowerHex)
	return bytesAsString(out), true
}

// sm9MAC returns SM3(Z || K2).
func sm9MAC(k2, z []byte) [32]byte {
	h := newSM3State()
	h.Update(z)
	h.Update(k2)
	var out [32]byte
	h.sum(&out)
	wipeBytes(h.buff[:])
	return out
}

// sm9SM4ECB encrypts or decrypts whole blocks of buf in place with SM4-ECB under key.
func sm9SM4ECB(key, buf []byte, decrypt bool) {
	var ks sm4Keys
	ks.expand(key)
	rk := &ks.rk
	if decrypt {
		rk = &ks.drk
	}
	for ; len(buf) >= sm4BlockSize; buf = buf[sm4BlockSize:] {
		y0, y1, y2, y3 := sm4EncryptWords(rk,
			binary.BigEndian.Uint32(buf[0:]), binary.BigEndian.Uint32(buf[4:]),
			binary.BigEndian.Uint32(buf[8:]), binary.BigEndian.Uint32(buf[12:]))
		binary.BigEndian.PutUint32(buf[0:], y0)
		binary.BigEndian.PutUint32(buf[4:], y1)
		binary.BigEndian.PutUint32(buf[8:], y2)
		binary.BigEndian.PutUint32(buf[12:], y3)
	}
	ks = sm4Keys{}
}

// SM9Decrypt decrypts a ciphertext from SM9Encrypt (lowercase hex) with userID's
// encryption private key, in the mode it was encrypted with. Every malformed or
// unauthentic ciphertext gives the same error; C3 is checked in constant time before
// anything is decrypted or unpadded.
func SM9Decrypt(ciphertext, userID, userPrivate string, mode SM9EncryptMode) ([]byte, error) {
	if mode != SM9ModeStream && mode != SM9ModeSM4 {
		return nil, errSM9Mode
	}
	de, ok := sm9ParseG2(userPrivate)
	if !ok {
		return nil, errInvalidPrivateKey
	}
	defer wipeG2(&de)

	const head = 2 * (sm9C1Len + sm9C3Len)
	if len(ciphertext) <= head || len(ciphertext)%2 != 0 {
		return nil, errSM9Decrypt
	}
	c1, ok := sm9ParseG1(ciphertext[:2*sm9C1Len], true)
	if !ok {
		return nil, errSM9Decrypt
	}
	var c3 [32]byte
	if !decodeHexLowerInto(c3[:], ciphertext[2*sm9C1Len:head]) {
		return nil, errSM9Decrypt
	}
	c2, err := hexToBytes(ciphertext[head:])
	if err != nil || uint64(len(c2)) > sm2MaxKDFBytes-sm9MACKeyLen {
		return nil, errSM9Decrypt
	}
	if mode == SM9ModeSM4 && len(c2)%sm4BlockSize != 0 {
		return nil, errSM9Decrypt
	}

	k1Len := sm9EncKeyLen(len(c2), mode)
	w := sm9Pair(&c1, &de)
	wb := sm9GTBytes(&w)
	cb := c1.bytes()
	k := sm9KDF(k1Len+sm9MACKeyLen, cb[1:], wb, stringAsBytes(userID))
	wipeBytes(wb)
	defer wipeBytes(k)
	k1, k2 := k[:k1Len], k[k1Len:]

	mac := sm9MAC(k2, c2)
	if sm9AllZero(k1) || subtle.ConstantTimeCompare(mac[:], c3[:]) != 1 {
		return nil, errSM9Decrypt
	}
	if mode == SM9ModeSM4 {
		sm9SM4ECB(k1, c2, true)
		plain, valid := sm4Unpad(c2)
		if !valid {
			return nil, errSM9Decrypt
		}
		return plain, nil
	}
	subtle.XORBytes(c2, c2, k1)
	return c2, nil
}

// --- key exchange ---

// SM9KeyExchangeResult holds the outcome of one side of the key exchange. SharedKey is
// secret, so fmt and encoding/json leave it out and encoding/gob refuses the type.
type SM9KeyExchangeResult struct {
	Success   bool
	Message   string
	SharedKey string `json:"-" xml:"-"` // hex
	SB        string // B's confirmation value, sent to A (respond)
	S2        string // the value B expects from A (respond)
	SA        string // A's confirmation value, sent to B (confirm)
}

// Format keeps the shared key out of logs.
func (r SM9KeyExchangeResult) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "SM9KeyExchangeResult{Success:%t Message:%q}", r.Success, r.Message)
}

// GobEncode refuses to serialize the shared key.
func (r SM9KeyExchangeResult) GobEncode() ([]byte, error) {
	return nil, errors.New("SM9KeyExchangeResult holds secrets and cannot be serialized")
}

// SM9ExchangeInit starts the key exchange with peerID: it draws the secret r and returns
// (rHex, RHex) with R = [r]([H1(peerID||hid)]P1 + Ppub-e). Send R to the peer and keep r
// secret. hid is normally SM9HIDExchange.
func SM9ExchangeInit(peerID, masterPublic string, hid byte) (string, string, error) {
	_, q, err := sm9EncSetup(peerID, masterPublic, hid)
	if err != nil {
		return "", "", err
	}
	r, err := sm9RandomScalar()
	if err != nil {
		return "", "", err
	}
	defer wipeLimbs(&r)
	big, ok := sm9ExchangeInitWithRandom(&q, &r)
	if !ok {
		return "", "", errRandom
	}
	return sm9ScalarHex(&r), big, nil
}

func sm9ExchangeInitWithRandom(q *sm9G1Aff, r *[4]uint64) (string, bool) {
	p, ok := sm9G1Mul(q, r)
	if !ok {
		return "", false
	}
	return sm9G1Hex(&p), true
}

// sm9ExchangeInputs is what both sides parse.
type sm9ExchangeInputs struct {
	master *sm9EncMaster
	de     sm9G2Aff
	r      [4]uint64
	ra, rb sm9G1Aff
}

func (in *sm9ExchangeInputs) wipe() {
	wipeLimbs(&in.r)
	wipeG2(&in.de)
}

func sm9ParseExchange(keyLen int, masterPublic, userPrivate, r, ra, rb string) (*sm9ExchangeInputs, string) {
	if keyLen < 1 || keyLen > sm2MaxKeyExchangeBytes {
		return nil, "invalid key length"
	}
	in := new(sm9ExchangeInputs)
	var ok bool
	if in.master, ok = sm9EncMasterFor(masterPublic); !ok {
		return nil, "invalid master public key"
	}
	if in.ra, ok = sm9ParseG1(ra, false); !ok {
		return nil, "invalid R_A"
	}
	if in.rb, ok = sm9ParseG1(rb, false); !ok {
		return nil, "invalid R_B"
	}
	if in.de, ok = sm9ParseG2(userPrivate); !ok {
		return nil, "invalid private key"
	}
	if in.r, ok = sm9ParseScalar(r); !ok {
		in.wipe()
		return nil, "invalid random value"
	}
	return in, ""
}

// sm9ExchangeValues returns the key and the confirmation hashes for g1, g2, g3:
// SK = KDF(ID_A || ID_B || R_A || R_B || g1 || g2 || g3), inner = SM3(g2 || g3 || ID_A ||
// ID_B || R_A || R_B), S_tag = SM3(tag || g1 || inner) for tags 0x82 and 0x83.
func sm9ExchangeValues(keyLen int, idA, idB string, in *sm9ExchangeInputs, g1, g2, g3 *sm9Fp12) (sk []byte, s82, s83 [32]byte) {
	b1, b2, b3 := sm9GTBytes(g1), sm9GTBytes(g2), sm9GTBytes(g3)
	defer wipeBytes(b1)
	defer wipeBytes(b2)
	defer wipeBytes(b3)
	ra, rb := in.ra.bytes(), in.rb.bytes()
	a, b := stringAsBytes(idA), stringAsBytes(idB)
	sk = sm9KDF(keyLen, a, b, ra[1:], rb[1:], b1, b2, b3)

	h := newSM3State()
	for _, p := range [][]byte{b2, b3, a, b, ra[1:], rb[1:]} {
		h.Update(p)
	}
	var inner [32]byte
	h.sum(&inner)
	wipeBytes(h.buff[:])
	for i, tag := range [2]byte{0x82, 0x83} {
		o := newSM3State()
		o.UpdateByte(tag)
		o.Update(b1)
		o.Update(inner[:])
		if i == 0 {
			o.sum(&s82)
		} else {
			o.sum(&s83)
		}
		wipeBytes(o.buff[:])
	}
	return sk, s82, s83
}

// SM9ExchangeRespond runs responder B's side: given R_A from A, its own rB and R_B, it
// computes the shared key, S_B to send to A, and S_2 to check A's reply against.
func SM9ExchangeRespond(keyLen int, idA, idB, masterPublic, userPrivateB, rB, RB, RA string) SM9KeyExchangeResult {
	in, msg := sm9ParseExchange(keyLen, masterPublic, userPrivateB, rB, RA, RB)
	if in == nil {
		return SM9KeyExchangeResult{Message: msg}
	}
	defer in.wipe()
	g1 := sm9Pair(&in.ra, &in.de)
	var g2, g3 sm9Fp12
	sm9GTExp(&g2, &in.master.g, &in.r)
	sm9GTExp(&g3, &g1, &in.r)
	sk, sb, s2 := sm9ExchangeValues(keyLen, idA, idB, in, &g1, &g2, &g3)
	res := SM9KeyExchangeResult{Success: true, SharedKey: bytesToHex(sk), SB: bytesToHex(sb[:]), S2: bytesToHex(s2[:])}
	wipeBytes(sk)
	return res
}

// SM9ExchangeConfirm runs initiator A's side: given R_B and S_B from B, it checks S_B in
// constant time and only then returns the shared key and S_A to send to B.
func SM9ExchangeConfirm(keyLen int, idA, idB, masterPublic, userPrivateA, rA, RA, RB, sB string) SM9KeyExchangeResult {
	var sbRaw [32]byte
	if len(sB) != 64 || !decodeHexLowerInto(sbRaw[:], sB) {
		return SM9KeyExchangeResult{Message: "invalid S_B"}
	}
	in, msg := sm9ParseExchange(keyLen, masterPublic, userPrivateA, rA, RA, RB)
	if in == nil {
		return SM9KeyExchangeResult{Message: msg}
	}
	defer in.wipe()
	var g1, g3 sm9Fp12
	sm9GTExp(&g1, &in.master.g, &in.r)
	g2 := sm9Pair(&in.rb, &in.de)
	sm9GTExp(&g3, &g2, &in.r)
	sk, s1, sa := sm9ExchangeValues(keyLen, idA, idB, in, &g1, &g2, &g3)
	defer wipeBytes(sk)
	if subtle.ConstantTimeCompare(s1[:], sbRaw[:]) != 1 {
		return SM9KeyExchangeResult{Message: "B's confirmation value does not match"}
	}
	return SM9KeyExchangeResult{Success: true, SharedKey: bytesToHex(sk), SA: bytesToHex(sa[:])}
}

// SM9ExchangeCheck is B's last step: it reports, in constant time, whether A's S_A equals
// the S_2 from SM9ExchangeRespond. Both must be 64 lowercase hex digits.
func SM9ExchangeCheck(s2, sA string) bool {
	var a, b [32]byte
	if len(s2) != 64 || len(sA) != 64 {
		return false
	}
	okA := decodeHexLowerInto(a[:], s2)
	okB := decodeHexLowerInto(b[:], sA)
	return okA && okB && subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
