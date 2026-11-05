package smx

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"strings"
)

// SM2KeySwapParams holds key exchange protocol state.
type SM2KeySwapParams struct {
	Sa      string
	Sb      string
	Ka      string
	Kb      string
	V       *ECPoint
	Za      []byte
	Zb      []byte
	Success bool
	Message string
}

const lowerHex = 0x27 // alphaOffset for lowercase digits, see hexSpread

// SM2GenKeyPair generates a new SM2 key pair.
// Returns (privateKeyHex, publicKeyHex).
func SM2GenKeyPair() (string, string) {
	d := randomScalar()
	r := sm2BaseMult(&d)
	pub := r.toAffinePoint()
	return d.ToHex(), pub.ToHexEncoded()
}

// SM2Encrypt encrypts plaintext using the public key. The result is the hex of
// C1 (04||x||y), C3 and C2, in that order.
func SM2Encrypt(plaintext, publicKey string) (string, error) {
	if len(plaintext) == 0 {
		return "", errors.New("plaintext cannot be empty")
	}
	pubPoint := ECPointFromHexEncoded(publicKey)
	if !pubPoint.IsOnCurve() {
		return "", errors.New("invalid public key")
	}
	for {
		k := randomScalar()
		if result, ok := sm2EncryptWithNonce(plaintext, &pubPoint, &k); ok {
			return result, nil
		}
	}
}

// sm2EncryptWithNonce encrypts with the nonce k and reports false if k must be replaced.
func sm2EncryptWithNonce(plaintext string, pub *ECPoint, k *BigInt256) (string, bool) {
	c1Jac := sm2BaseMult(k)
	p2Jac := multiplyJacobian(pub, k)
	c1, p2 := pairToAffine(&c1Jac, &p2Jac)
	if p2.Infinity {
		return "", false
	}

	var c1Bytes [65]byte
	c1.encodeTo(&c1Bytes)
	var p2Bytes [65]byte
	p2.encodeTo(&p2Bytes)
	x2, y2 := p2Bytes[1:33], p2Bytes[33:65]

	// One buffer holds the whole result; the raw C2 is built in its last len(plaintext)
	// bytes and then expanded to hex in place.
	const c2Start = 130 + 64
	out := make([]byte, c2Start+2*len(plaintext))
	c2 := out[c2Start+len(plaintext):]
	message := stringAsBytes(plaintext)
	if allZero := kdfXOR(c2, message, p2Bytes[1:]); allZero {
		return "", false
	}

	h := SM3{v: sm3IV}
	h.Update(x2)
	h.Update(message)
	h.Update(y2)
	var c3 [32]byte
	h.sum(&c3)

	encodeHexTo(out[:130], c1Bytes[:], lowerHex)
	encodeHexTo(out[130:c2Start], c3[:], lowerHex)
	encodeHexTo(out[c2Start:], c2, lowerHex)
	return bytesAsString(out), true
}

// SM2Decrypt decrypts ciphertext using the private key.
func SM2Decrypt(ciphertext, privateKey string) (string, error) {
	if len(ciphertext) < 130+64 {
		return "", errors.New("ciphertext too short")
	}

	c1 := ECPointFromHexEncoded(ciphertext[:130])
	if !c1.IsOnCurve() {
		return "", errors.New("invalid C1 point")
	}

	c3, err := hexToBytes(ciphertext[130:194])
	if err != nil {
		return "", errors.New("invalid C3 hex")
	}
	c2, err := hexToBytes(ciphertext[194:])
	if err != nil {
		return "", errors.New("invalid C2 hex")
	}

	d := BigInt256FromHex(privateKey)
	p2 := c1.Multiply(&d)
	if p2.Infinity {
		return "", errors.New("invalid decryption")
	}

	var p2Bytes [65]byte
	p2.encodeTo(&p2Bytes)
	kdfXOR(c2, c2, p2Bytes[1:])

	h := SM3{v: sm3IV}
	h.Update(p2Bytes[1:33])
	h.Update(c2)
	h.Update(p2Bytes[33:65])
	var computed [32]byte
	h.sum(&computed)

	if !bytesEqual(computed[:], c3) {
		return "", errors.New("decryption verification failed")
	}
	return bytesAsString(c2), nil
}

// SM2Sign signs a message with userID and private key.
func SM2Sign(userID, message, privateKey string) (string, error) {
	d := BigInt256FromHex(privateKey)
	for {
		k := randomScalar()
		if sig, ok := sm2SignWithNonce(userID, message, &d, &k); ok {
			return sig, nil
		}
	}
}

// sm2SignWithNonce signs with the nonce k and reports false if k must be replaced.
func sm2SignWithNonce(userID, message string, d, k *BigInt256) (string, bool) {
	pubJac := sm2BaseMult(d)
	kJac := sm2BaseMult(k)
	pub, kp := pairToAffine(&pubJac, &kJac)

	e := sm2MessageDigest(userID, message, &pub)
	x1 := kp.X.value

	r := e.ModAdd(&x1, &SM2_N)
	if r.IsZero() {
		return "", false
	}
	rk, _ := r.Add(k)
	if limbsEqual(&rk.limbs, &SM2_N.limbs) {
		return "", false
	}

	// s = (1 + d)^-1 * (k - r*d) mod n
	dPlus1, _ := d.Add(&bigOne)
	var dPlus1Inv, rd, s BigInt256
	scalarInvert(&dPlus1Inv.limbs, &dPlus1.limbs)
	scalarMul(&rd.limbs, &r.limbs, &d.limbs)
	kMinusRD := k.ModSub(&rd, &SM2_N)
	scalarMul(&s.limbs, &kMinusRD.limbs, &dPlus1Inv.limbs)
	if s.IsZero() {
		return "", false
	}

	var raw [32]byte
	out := make([]byte, 64+1+64)
	putLimbsBE(&raw, &r.limbs)
	encodeHexTo(out[:64], raw[:], lowerHex)
	out[64] = 'h'
	putLimbsBE(&raw, &s.limbs)
	encodeHexTo(out[65:], raw[:], lowerHex)
	return bytesAsString(out), true
}

// SM2Verify verifies a signature.
func SM2Verify(userID, signature, message, publicKey string) bool {
	sep := strings.IndexByte(signature, 'h')
	if sep < 0 || strings.LastIndexByte(signature, 'h') != sep {
		return false
	}
	r := BigInt256FromHex(signature[:sep])
	s := BigInt256FromHex(signature[sep+1:])

	if r.IsZero() || r.Compare(&SM2_N) >= 0 {
		return false
	}
	if s.IsZero() || s.Compare(&SM2_N) >= 0 {
		return false
	}

	pubPoint := ECPointFromHexEncoded(publicKey)
	if !pubPoint.IsOnCurve() {
		return false
	}

	e := sm2MessageDigest(userID, message, &pubPoint)

	t := r.ModAdd(&s, &SM2_N)
	if t.IsZero() {
		return false
	}

	var sum jacPoint
	if pubPoint.Infinity {
		jacDoubleScalarMultVar(&sum, &s.limbs, nil, nil)
	} else {
		jp := jacFromAffinePoint(&pubPoint)
		jacDoubleScalarMultVar(&sum, &s.limbs, &t.limbs, &jp)
	}
	if feIsZeroMask(&sum.z) != 0 {
		return false
	}
	return verifyCheckR(&sum, &e, &r)
}

// verifyFastLimit is 2n - p. Below it e + x, for any field element x, is correctly
// reduced by the single subtraction in ModAdd, so the projective comparison in
// verifyCheckR matches the affine computation exactly.
var verifyFastLimit = BigInt256{limbs: [4]uint64{
	0xA777E81273AA8247, 0xE407BED7438C0A55, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFEFFFFFFFF,
}}

// verifyCheckR reports whether r == (e + x) mod n for the finite point p = (x, ...). It
// avoids a field inversion by comparing X with x'*Z^2 for each candidate x', which are
// r - e mod n and that value plus n if it is still below p.
func verifyCheckR(p *jacPoint, e, r *BigInt256) bool {
	if e.Compare(&verifyFastLimit) >= 0 {
		// Astronomically unlikely, so simply take the affine path.
		a := p.toAffinePoint()
		computed := e.ModAdd(&a.X.value, &SM2_N)
		return *r == computed
	}

	var zz fe
	feSqr(&zz, &p.z)
	candidate := r.ModSub(e, &SM2_N)
	if projectiveXEquals(p, &zz, &candidate) {
		return true
	}
	second, carry := candidate.Add(&SM2_N)
	return carry == 0 && second.Compare(&SM2_P) < 0 && projectiveXEquals(p, &zz, &second)
}

func projectiveXEquals(p *jacPoint, zz *fe, x *BigInt256) bool {
	var m fe
	feToMont(&m, &x.limbs)
	feMul(&m, &m, zz)
	return m == p.x
}

// SM2GetSb computes B's key exchange parameters.
func SM2GetSb(byteLen int, pA, rA, pB ECPoint, dB *BigInt256, rB ECPoint, rb *BigInt256, idA, idB string) SM2KeySwapParams {
	result := SM2KeySwapParams{}

	x2Bar := calcXBar(&rB.X.value)
	tb := calcT(rb, dB, &x2Bar)

	if !rA.IsOnCurve() {
		result.Message = "RA point is not on curve"
		return result
	}

	x1Bar := calcXBar(&rA.X.value)
	v := calcSharedPoint(&tb, &x1Bar, &pA, &rA)
	if v.Infinity {
		result.Message = "V is point at infinity"
		return result
	}

	za := sm2Z([]byte(idA), &pA)
	zb := sm2Z([]byte(idB), &pB)

	kb := kdfKeySwap(byteLen, &v, za[:], zb[:])
	sb := createS(0x02, &v, za[:], zb[:], &rA, &rB)

	result.Sb = bytesToHex(sb[:])
	result.Kb = bytesToHex(kb)
	result.V = &v
	result.Za = za[:]
	result.Zb = zb[:]
	result.Success = true
	return result
}

// SM2GetSa computes A's key exchange parameters.
func SM2GetSa(byteLen int, pB, rB, pA ECPoint, dA *BigInt256, rA ECPoint, ra *BigInt256, idA, idB string, sb []byte) SM2KeySwapParams {
	result := SM2KeySwapParams{}

	x1Bar := calcXBar(&rA.X.value)
	ta := calcT(ra, dA, &x1Bar)

	if !rB.IsOnCurve() {
		result.Message = "RB point is not on curve"
		return result
	}

	x2Bar := calcXBar(&rB.X.value)
	u := calcSharedPoint(&ta, &x2Bar, &pB, &rB)
	if u.Infinity {
		result.Message = "U is point at infinity"
		return result
	}

	za := sm2Z([]byte(idA), &pA)
	zb := sm2Z([]byte(idB), &pB)

	ka := kdfKeySwap(byteLen, &u, za[:], zb[:])
	s1 := createS(0x02, &u, za[:], zb[:], &rA, &rB)

	if !bytesEqual(s1[:], sb) {
		result.Message = "B's verification value does not match"
		return result
	}

	sa := createS(0x03, &u, za[:], zb[:], &rA, &rB)
	result.Sa = bytesToHex(sa[:])
	result.Ka = bytesToHex(ka)
	result.Success = true
	return result
}

// SM2CheckSa verifies A's key exchange value Sa.
func SM2CheckSa(v ECPoint, za, zb []byte, rA, rB ECPoint, sa []byte) bool {
	s2 := createS(0x03, &v, za, zb, &rA, &rB)
	return bytesEqual(s2[:], sa)
}

// SM2DecodePoint decodes a public key hex string to an ECPoint.
func SM2DecodePoint(hexStr string) ECPoint {
	return ECPointFromHexEncoded(hexStr)
}

// SM2GetPublicKey computes the public key from a private key.
func SM2GetPublicKey(privateKey *BigInt256) ECPoint {
	r := sm2BaseMult(privateKey)
	return r.toAffinePoint()
}

// --- internal helpers ---

func randomBigInt() BigInt256 {
	var b [32]byte
	rand.Read(b[:])
	return BigInt256FromBEBytes(b[:])
}

// randomScalar returns a uniformly random value in [1, n-1], using rejection sampling
// with a constant-time range check.
func randomScalar() BigInt256 {
	for {
		k := randomBigInt()
		if scalarInRange(&k.limbs) {
			return k
		}
	}
}

// kdfXOR sets dst to src XOR the SM3 KDF stream for seed and reports whether the
// stream was all zeros. dst and src must have the same length and may be the same slice.
//
// The state after the whole blocks of seed is reused for every counter value.
func kdfXOR(dst, src, seed []byte) (allZero bool) {
	base := SM3{v: sm3IV}
	base.Update(seed)

	var accumulated byte
	var digest [32]byte
	var counter [4]byte
	for ct, off := uint32(1), 0; off < len(dst); ct, off = ct+1, off+32 {
		h := base
		binary.BigEndian.PutUint32(counter[:], ct)
		h.Update(counter[:])
		h.sum(&digest)
		n := subtle.XORBytes(dst[off:], src[off:], digest[:])
		for _, b := range digest[:n] {
			accumulated |= b
		}
	}
	return accumulated == 0
}

func kdfKeySwap(keylen int, vu *ECPoint, za, zb []byte) []byte {
	seed := make([]byte, 0, 64+len(za)+len(zb))
	var point [65]byte
	vu.encodeTo(&point)
	seed = append(seed, point[1:]...)
	seed = append(seed, za...)
	seed = append(seed, zb...)

	key := make([]byte, keylen)
	kdfXOR(key, key, seed)
	return key
}

// sm2CurveParams is a||b||Gx||Gy, the fixed middle of the Z value.
var sm2CurveParams = func() []byte {
	out := make([]byte, 0, 128)
	for _, v := range []*FpElement{&SM2_A, &SM2_B, &SM2_GX, &SM2_GY} {
		b := v.ToBEBytes()
		out = append(out, b[:]...)
	}
	return out
}()

// sm2Z computes Z = SM3(ENTL || ID || a || b || Gx || Gy || x || y).
func sm2Z(userID []byte, publicKey *ECPoint) [32]byte {
	h := SM3{v: sm3IV}
	entl := uint16(len(userID) * 8)
	h.UpdateByte(byte(entl >> 8))
	h.UpdateByte(byte(entl))
	h.Update(userID)
	h.Update(sm2CurveParams)

	var point [65]byte
	publicKey.encodeTo(&point)
	h.Update(point[1:])

	var z [32]byte
	h.sum(&z)
	return z
}

// userSM3Z is sm2Z with the historical signature.
func userSM3Z(userID []byte, publicKey ECPoint) []byte {
	z := sm2Z(userID, &publicKey)
	return z[:]
}

// sm2MessageDigest computes e = SM3(Z || message) as an integer.
func sm2MessageDigest(userID, message string, pub *ECPoint) BigInt256 {
	z := sm2Z(stringAsBytes(userID), pub)
	h := SM3{v: sm3IV}
	h.Update(z[:])
	h.Update(stringAsBytes(message))
	var digest [32]byte
	h.sum(&digest)
	return BigInt256FromBEBytes(digest[:])
}

// calcXBar computes 2^127 + (x mod 2^127).
func calcXBar(x *BigInt256) BigInt256 {
	return BigInt256{limbs: [4]uint64{x.limbs[0], x.limbs[1] | 1<<63}}
}

// calcT computes (d + xBar*r) mod n. d and r are secret.
func calcT(r, d, xBar *BigInt256) BigInt256 {
	var xr BigInt256
	scalarMul(&xr.limbs, &xBar.limbs, &r.limbs)
	return d.ModAdd(&xr, &SM2_N)
}

// calcSharedPoint computes [t](p + [xBar]r). p, r and xBar are public, so the inner
// multiplication may be variable time; the outer one uses the secret t and is not.
func calcSharedPoint(t, xBar *BigInt256, p, r *ECPoint) ECPoint {
	var sum jacPoint
	if !r.Infinity {
		jr := jacFromAffinePoint(r)
		jacScalarMultVar(&sum, &jr, &xBar.limbs)
	}
	if !p.Infinity {
		jp := jacFromAffinePoint(p)
		jacAddVar(&sum, &sum, &jp)
	}
	if feIsZeroMask(&sum.z) != 0 {
		return ECPointInfinity()
	}
	scalar := scalarReduce(&t.limbs)
	var result jacPoint
	jacScalarMult(&result, &sum, &scalar)
	return result.toAffinePoint()
}

func createS(tag byte, vu *ECPoint, za, zb []byte, ra, rb *ECPoint) [32]byte {
	var v, a, b [65]byte
	vu.encodeTo(&v)
	ra.encodeTo(&a)
	rb.encodeTo(&b)

	h := SM3{v: sm3IV}
	h.Update(v[1:33])
	h.Update(za)
	h.Update(zb)
	h.Update(a[1:])
	h.Update(b[1:])
	var inner [32]byte
	h.sum(&inner)

	outer := SM3{v: sm3IV}
	outer.UpdateByte(tag)
	outer.Update(v[33:])
	outer.Update(inner[:])
	var out [32]byte
	outer.sum(&out)
	return out
}

// bytesEqual compares in constant time for inputs of equal length.
func bytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
