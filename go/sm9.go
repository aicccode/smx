package smx

import (
	"encoding/binary"
	"errors"
)

// SM9 identity-based cryptography (GB/T 38635): key generation, signatures, key
// encapsulation, public key encryption and key exchange over the 256-bit BN curve of the
// standard.
//
// Keys and points are hex strings, as in the SM2 API. Keys and public keys may use
// either case; signatures and ciphertexts are lowercase only, so each value has exactly
// one accepted encoding. Encodings: scalars 32 bytes big endian, G1 points 04||x||y,
// G2 points 04||x1||x0||y1||y0 (high Fq2 component first), signatures h||S and
// ciphertexts C1||C3||C2, with C1 a G1 point.
//
// Secret scalars (master keys, the random r, the signing l) drive scalar
// multiplications and GT exponentiations with fixed signed windows and masked
// full-table lookups; field arithmetic is in fixed-width Montgomery limbs with no
// secret-dependent branches. Verification and public-key paths may be variable time.

// The hid values of GB/T 38635.
const (
	SM9HIDSign     byte = 0x01
	SM9HIDExchange byte = 0x02
	SM9HIDEncrypt  byte = 0x03
)

const (
	sm9ScalarHexLen    = 64
	sm9G1HexLen        = 130
	sm9G2HexLen        = 258
	sm9SignatureHexLen = sm9ScalarHexLen + sm9G1HexLen
)

var (
	errSM9InvalidUserKey = errors.New("sm9: invalid user key: H1(ID||hid) + master key is 0 mod N")
	errSM9InvalidKeyLen  = errors.New("sm9: invalid key length")
)

// --- parsing ---

// sm9ParseScalar parses exactly 64 hex digits of either case holding a value in
// [1, N-1]. The digits and the range are checked in constant time.
func sm9ParseScalar(s string) ([4]uint64, bool) {
	if len(s) != sm9ScalarHexLen {
		return [4]uint64{}, false
	}
	var raw [32]byte
	valid := decodeHexInto(raw[:], s)
	k := BigInt256FromBEBytes(raw[:]).limbs
	wipeBytes(raw[:])
	if !valid || !sm9NInRange(&k) {
		wipeLimbs(&k)
		return [4]uint64{}, false
	}
	return k, true
}

// sm9ParseG1 parses the hex of a G1 point; lowerOnly refuses uppercase digits.
func sm9ParseG1(s string, lowerOnly bool) (sm9G1Aff, bool) {
	if len(s) != sm9G1HexLen {
		return sm9G1Aff{}, false
	}
	var raw [65]byte
	var ok bool
	if lowerOnly {
		ok = decodeHexLowerInto(raw[:], s)
	} else {
		ok = decodeHexInto(raw[:], s)
	}
	if !ok {
		return sm9G1Aff{}, false
	}
	return sm9G1FromBytes(raw[:])
}

// sm9ParseG2 parses the hex of a G2 point, of either case, including the subgroup check.
func sm9ParseG2(s string) (sm9G2Aff, bool) {
	if len(s) != sm9G2HexLen {
		return sm9G2Aff{}, false
	}
	var raw [129]byte
	ok := decodeHexInto(raw[:], s)
	defer wipeBytes(raw[:])
	if !ok {
		return sm9G2Aff{}, false
	}
	return sm9G2FromBytes(raw[:])
}

func sm9ScalarHex(k *[4]uint64) string {
	var raw [32]byte
	putLimbsBE(&raw, k)
	s := bytesToHex(raw[:])
	wipeBytes(raw[:])
	return s
}

func sm9G1Hex(p *sm9G1Aff) string {
	b := p.bytes()
	return bytesToHex(b[:])
}

func sm9G2Hex(p *sm9G2Aff) string {
	b := p.bytes()
	return bytesToHex(b[:])
}

// sm9RandomScalar returns a uniform value in [1, N-1] from the OS CSPRNG, by rejection
// sampling with a bounded number of attempts.
func sm9RandomScalar() ([4]uint64, error) {
	for i := 0; i < sm2MaxAttempts; i++ {
		var k BigInt256
		if err := readRandomBigInt(&k); err != nil {
			return [4]uint64{}, err
		}
		if sm9NInRange(&k.limbs) {
			return k.limbs, nil
		}
		wipeLimbs(&k.limbs)
	}
	return [4]uint64{}, errRandom
}

// --- hashes ---

// sm9H is H1 (tag 1) or H2 (tag 2) of GB/T 38635.2 over the concatenation of parts:
// Ha = SM3(tag||Z||1) || SM3(tag||Z||2)[:8], result (Ha mod (N-1)) + 1.
func sm9H(tag byte, parts ...[]byte) [4]uint64 {
	var ha [40]byte
	var digest [32]byte
	for ct := uint32(1); ct <= 2; ct++ {
		h := newSM3State()
		h.UpdateByte(tag)
		for _, p := range parts {
			h.Update(p)
		}
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], ct)
		h.Update(c[:])
		h.sum(&digest)
		wipeBytes(h.buff[:])
		copy(ha[32*(ct-1):], digest[:])
	}
	out := sm9HashReduce(&ha)
	wipeBytes(ha[:])
	wipeBytes(digest[:])
	return out
}

// sm9H1 returns H1(ID || hid).
func sm9H1(id []byte, hid byte) [4]uint64 {
	return sm9H(0x01, id, []byte{hid})
}

// sm9KDF returns klen bytes of SM3(Z || ct) for ct = 1, 2, ... over the parts of Z.
func sm9KDF(klen int, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	seed := make([]byte, 0, n)
	for _, p := range parts {
		seed = append(seed, p...)
	}
	out := make([]byte, klen)
	kdfXOR(out, out, seed)
	wipeBytes(seed)
	return out
}

func sm9AllZero(b []byte) bool {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return acc == 0
}

func sm9GTBytes(x *sm9Fp12) []byte {
	var out [384]byte
	sm9Fp12Bytes(&out, x)
	return out[:]
}

// --- master and user keys ---

// sm9MasterKeyPair draws a master private key and derives its public key.
func sm9MasterKeyPair(public func(k *[4]uint64) string) (string, string, error) {
	k, err := sm9RandomScalar()
	if err != nil {
		return "", "", err
	}
	defer wipeLimbs(&k)
	return sm9ScalarHex(&k), public(&k), nil
}

func sm9SignPublic(ks *[4]uint64) string {
	p, _ := sm9G2Mul(&sm9P2, ks)
	return sm9G2Hex(&p)
}

func sm9EncPublic(ke *[4]uint64) string {
	p, _ := sm9G1Mul(&sm9P1, ke)
	return sm9G1Hex(&p)
}

// SM9GenerateSignMasterKey generates a signing master key pair: the private key ks and
// the public key Ppub-s = [ks]P2 (a G2 point), as hex.
func SM9GenerateSignMasterKey() (masterPrivate, masterPublic string, err error) {
	return sm9MasterKeyPair(sm9SignPublic)
}

// SM9SignMasterPublicKey derives the signing master public key from the private key.
func SM9SignMasterPublicKey(masterPrivate string) (string, error) {
	ks, ok := sm9ParseScalar(masterPrivate)
	if !ok {
		return "", errInvalidPrivateKey
	}
	defer wipeLimbs(&ks)
	return sm9SignPublic(&ks), nil
}

// SM9GenerateEncryptMasterKey generates an encryption master key pair: the private key
// ke and the public key Ppub-e = [ke]P1 (a G1 point), as hex. The same key pair serves
// key encapsulation and key exchange.
func SM9GenerateEncryptMasterKey() (masterPrivate, masterPublic string, err error) {
	return sm9MasterKeyPair(sm9EncPublic)
}

// SM9EncryptMasterPublicKey derives the encryption master public key from the private key.
func SM9EncryptMasterPublicKey(masterPrivate string) (string, error) {
	ke, ok := sm9ParseScalar(masterPrivate)
	if !ok {
		return "", errInvalidPrivateKey
	}
	defer wipeLimbs(&ke)
	return sm9EncPublic(&ke), nil
}

// sm9UserScalar returns master * (H1(ID||hid) + master)^-1 mod N, or false when the sum
// is zero.
func sm9UserScalar(master *[4]uint64, userID string, hid byte) ([4]uint64, bool) {
	h1 := sm9H1(stringAsBytes(userID), hid)
	var t1, inv, k [4]uint64
	sm9NAdd(&t1, &h1, master)
	if sm9IsZero(&t1) {
		return k, false
	}
	sm9NInv(&inv, &t1)
	sm9NMul(&k, master, &inv)
	wipeLimbs(&t1)
	wipeLimbs(&inv)
	return k, true
}

// SM9GenerateSignUserKey derives the signing private key ds = [ks/(H1(ID||hid)+ks)]P1 of
// userID (a G1 point, hex). hid is normally SM9HIDSign.
func SM9GenerateSignUserKey(masterPrivate, userID string, hid byte) (string, error) {
	ks, ok := sm9ParseScalar(masterPrivate)
	if !ok {
		return "", errInvalidPrivateKey
	}
	defer wipeLimbs(&ks)
	k, ok := sm9UserScalar(&ks, userID, hid)
	if !ok {
		return "", errSM9InvalidUserKey
	}
	defer wipeLimbs(&k)
	ds, _ := sm9G1Mul(&sm9P1, &k)
	return sm9G1Hex(&ds), nil
}

// SM9GenerateEncryptUserKey derives the encryption private key de = [ke/(H1(ID||hid)+ke)]P2
// of userID (a G2 point, hex), used for decryption, decapsulation and key exchange. hid
// is normally SM9HIDEncrypt, or SM9HIDExchange for key exchange.
func SM9GenerateEncryptUserKey(masterPrivate, userID string, hid byte) (string, error) {
	ke, ok := sm9ParseScalar(masterPrivate)
	if !ok {
		return "", errInvalidPrivateKey
	}
	defer wipeLimbs(&ke)
	k, ok := sm9UserScalar(&ke, userID, hid)
	if !ok {
		return "", errSM9InvalidUserKey
	}
	defer wipeLimbs(&k)
	de, _ := sm9G2Mul(&sm9P2, &k)
	return sm9G2Hex(&de), nil
}

// --- signatures ---

// SM9Sign signs message with the user's signing private key (G1, hex) under the signing
// master public key (G2, hex). The signature is the lowercase hex of h || S, 97 bytes.
func SM9Sign(message []byte, userPrivate, masterPublic string) (string, error) {
	ds, ok := sm9ParseG1(userPrivate, false)
	if !ok {
		return "", errInvalidPrivateKey
	}
	defer wipeG1(&ds)
	master, ok := sm9SignMasterFor(masterPublic)
	if !ok {
		return "", errInvalidPublicKey
	}
	for i := 0; i < sm2MaxAttempts; i++ {
		r, err := sm9RandomScalar()
		if err != nil {
			return "", err
		}
		sig, ok := sm9SignWithRandom(message, &ds, &master.g, &r)
		wipeLimbs(&r)
		if ok {
			return sig, nil
		}
	}
	return "", errRandom
}

// sm9SignWithRandom signs with the random r in [1, N-1], given g = e(P1, Ppub-s), and
// reports false if r must be replaced (l == 0).
func sm9SignWithRandom(message []byte, ds *sm9G1Aff, g *sm9Fp12, r *[4]uint64) (string, bool) {
	var w sm9Fp12
	sm9GTExp(&w, g, r)
	wb := sm9GTBytes(&w)
	h := sm9H(0x02, message, wb)
	wipeBytes(wb)
	var l [4]uint64
	sm9NSub(&l, r, &h)
	defer wipeLimbs(&l)
	if sm9IsZero(&l) {
		return "", false
	}
	s, ok := sm9G1Mul(ds, &l)
	if !ok {
		return "", false
	}
	var raw [32 + 65]byte
	putLimbsBE((*[32]byte)(raw[:32]), &h)
	sb := s.bytes()
	copy(raw[32:], sb[:])
	return bytesToHex(raw[:]), true
}

// SM9Verify verifies a signature of message by userID under the signing master public
// key. Any malformed input gives false.
func SM9Verify(message []byte, signature, userID, masterPublic string, hid byte) bool {
	if len(signature) != sm9SignatureHexLen {
		return false
	}
	var hRaw [32]byte
	if !decodeHexLowerInto(hRaw[:], signature[:sm9ScalarHexLen]) {
		return false
	}
	h := BigInt256FromBEBytes(hRaw[:]).limbs
	if !sm9NInRange(&h) {
		return false
	}
	s, ok := sm9ParseG1(signature[sm9ScalarHexLen:], true)
	if !ok {
		return false
	}
	master, ok := sm9SignMasterFor(masterPublic)
	if !ok {
		return false
	}

	var t sm9Fp12
	sm9GTExp(&t, &master.g, &h)

	h1 := sm9H1(stringAsBytes(userID), hid)
	var pj sm9G2Jac
	p2 := sm9P2.jac()
	sm9G2ScalarMultVar(&pj, &p2, &h1)
	pubJ := master.ppub.jac()
	sm9G2AddVar(&pj, &pj, &pubJ)
	u := sm9Fp12One()
	if pa, finite := pj.toAffine(); finite {
		u = sm9Pair(&s, &pa)
	}
	var w sm9Fp12
	sm9Fp12Mul(&w, &u, &t)
	h2 := sm9H(0x02, message, sm9GTBytes(&w))
	return limbsEqual(&h2, &h)
}

func wipeG1(p *sm9G1Aff) {
	wipeLimbs((*[4]uint64)(&p.x))
	wipeLimbs((*[4]uint64)(&p.y))
}

func wipeG2(p *sm9G2Aff) {
	for _, f := range []*sm9Fp{&p.x.a0, &p.x.a1, &p.y.a0, &p.y.a1} {
		wipeLimbs((*[4]uint64)(f))
	}
}
