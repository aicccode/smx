package smx

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime"
)

const (
	// sm2MaxUserIDBytes is the longest user ID: ENTL holds its length in bits in 16 bits.
	sm2MaxUserIDBytes = 8191

	// sm2MaxKDFBytes is the KDF's limit of (2^32 - 1) hash blocks, from GB/T 32918.
	sm2MaxKDFBytes = (1<<32 - 1) * 32

	// sm2MaxKeyExchangeBytes bounds the key length in the key exchange.
	sm2MaxKeyExchangeBytes = 1 << 20

	// sm2MaxAttempts bounds every retry loop. One attempt fails with probability around
	// 2^-32 at worst, so reaching the limit means the random source is broken.
	sm2MaxAttempts = 64

	sm2SignatureHexLen = 64 + 1 + 64
	sm2PointHexLen     = 130
	sm2C3HexLen        = 64
)

var (
	errInvalidPublicKey  = errors.New("invalid public key")
	errInvalidPrivateKey = errors.New("invalid private key")
	errUserIDTooLong     = errors.New("user ID too long")
	errRandom            = errors.New("random number generation failed")
	errPlaintextTooLong  = errors.New("plaintext too long")
)

// sm2RandReader is the operating system's CSPRNG. It is captured once, so nothing that
// later replaces crypto/rand.Reader can change where nonces come from.
var sm2RandReader io.Reader = rand.Reader

// SM2KeySwapParams holds key exchange protocol state. Ka, Kb and V are secret.
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

// Format keeps the shared secrets out of logs: every fmt verb prints only the outcome.
func (p SM2KeySwapParams) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "SM2KeySwapParams{Success:%t Message:%q}", p.Success, p.Message)
}

// parsePrivateKey parses exactly 64 hex digits holding a value in [1, n-2]. The digits
// and the range are checked in constant time.
func parsePrivateKey(s string) (BigInt256, error) {
	if len(s) != 64 {
		return BigInt256{}, errInvalidPrivateKey
	}
	var raw [32]byte
	valid := decodeHexInto(raw[:], s)
	d := BigInt256FromBEBytes(raw[:])
	wipeBytes(raw[:])
	if !valid || !privateKeyInRange(&d.limbs) {
		return BigInt256{}, errInvalidPrivateKey
	}
	return d, nil
}

// SM2ParsePublicKey decodes a public key from the hex of 04||x||y, exactly 130 digits. It
// returns an error unless x and y are below p and the point is on the curve.
func SM2ParsePublicKey(s string) (ECPoint, error) {
	p, ok := parseHexPoint(s)
	if !ok {
		return ECPointInfinity(), errInvalidPublicKey
	}
	return p, nil
}

// SM2GenerateKeyPair generates a new SM2 key pair, returning (privateKeyHex, publicKeyHex),
// or an error if the operating system's random source fails.
func SM2GenerateKeyPair() (string, string, error) {
	for i := 0; i < sm2MaxAttempts; i++ {
		var d BigInt256
		if err := readRandomBigInt(&d); err != nil {
			return "", "", err
		}
		if !privateKeyInRange(&d.limbs) {
			continue
		}
		r := sm2BaseMult(&d)
		pub := r.toAffinePoint()
		priv := d.ToHex()
		wipeLimbs(&d.limbs)
		return priv, pub.ToHexEncoded(), nil
	}
	return "", "", errRandom
}

// SM2GenKeyPair generates a new SM2 key pair, returning (privateKeyHex, publicKeyHex). This
// signature cannot report failure, so if the random source fails both strings are
// empty. SM2GenerateKeyPair returns the error instead.
func SM2GenKeyPair() (string, string) {
	priv, pub, err := SM2GenerateKeyPair()
	if err != nil {
		return "", ""
	}
	return priv, pub
}

// SM2Encrypt encrypts plaintext using the public key. The result is the hex of
// C1 (04||x||y), C3 and C2, in that order.
func SM2Encrypt(plaintext, publicKey string) (string, error) {
	if len(plaintext) == 0 {
		return "", errors.New("plaintext cannot be empty")
	}
	if !sm2PlaintextLenValid(uint64(len(plaintext))) {
		return "", errPlaintextTooLong
	}
	pubPoint, ok := parseHexPoint(publicKey)
	if !ok {
		return "", errInvalidPublicKey
	}
	for i := 0; i < sm2MaxAttempts; i++ {
		k, err := randomScalar()
		if err != nil {
			return "", err
		}
		result, ok := sm2EncryptWithNonce(plaintext, &pubPoint, &k)
		wipeLimbs(&k.limbs)
		if ok {
			return result, nil
		}
	}
	return "", errRandom
}

// sm2PlaintextLenValid checks the KDF limit and that the hex result fits in an int.
func sm2PlaintextLenValid(n uint64) bool {
	return n <= sm2MaxKDFBytes && n <= (math.MaxInt-sm2PointHexLen-sm2C3HexLen)/2
}

// sm2EncryptWithNonce encrypts with the nonce k and reports false if k must be replaced.
// k must be in [1, n-1] and pub a validated point.
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
	defer wipeBytes(p2Bytes[:])
	x2, y2 := p2Bytes[1:33], p2Bytes[33:65]

	// One buffer holds the whole result; the raw C2 is built in its last len(plaintext)
	// bytes and then expanded to hex in place.
	const c2Start = sm2PointHexLen + sm2C3HexLen
	out := make([]byte, c2Start+2*len(plaintext))
	c2 := out[c2Start+len(plaintext):]
	message := stringAsBytes(plaintext)
	if allZero := kdfXOR(c2, message, p2Bytes[1:]); allZero {
		return "", false
	}

	h := newSM3State()
	h.Update(x2)
	h.Update(message)
	h.Update(y2)
	var c3 [32]byte
	h.sum(&c3)
	wipeBytes(h.buff[:])

	encodeHexTo(out[:sm2PointHexLen], c1Bytes[:], lowerHex)
	encodeHexTo(out[sm2PointHexLen:c2Start], c3[:], lowerHex)
	encodeHexTo(out[c2Start:], c2, lowerHex)
	return bytesAsString(out), true
}

// SM2Decrypt decrypts ciphertext using the private key.
func SM2Decrypt(ciphertext, privateKey string) (string, error) {
	const minLen = sm2PointHexLen + sm2C3HexLen + 2
	if len(ciphertext) < minLen {
		return "", errors.New("ciphertext too short")
	}

	c1, ok := parseHexPoint(ciphertext[:sm2PointHexLen])
	if !ok {
		return "", errors.New("invalid C1 point")
	}

	c3, err := hexToBytes(ciphertext[sm2PointHexLen : sm2PointHexLen+sm2C3HexLen])
	if err != nil {
		return "", errors.New("invalid C3 hex")
	}
	c2, err := hexToBytes(ciphertext[sm2PointHexLen+sm2C3HexLen:])
	if err != nil {
		return "", errors.New("invalid C2 hex")
	}
	if uint64(len(c2)) > sm2MaxKDFBytes {
		return "", errors.New("ciphertext too long")
	}

	d, err := parsePrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	p2 := c1.Multiply(&d)
	wipeLimbs(&d.limbs)
	if p2.Infinity {
		return "", errors.New("invalid decryption")
	}

	var p2Bytes [65]byte
	p2.encodeTo(&p2Bytes)
	defer wipeBytes(p2Bytes[:])
	allZero := kdfXOR(c2, c2, p2Bytes[1:])

	h := newSM3State()
	h.Update(p2Bytes[1:33])
	h.Update(c2)
	h.Update(p2Bytes[33:65])
	var computed [32]byte
	h.sum(&computed)
	wipeBytes(h.buff[:])

	if !bytesEqual(computed[:], c3) || allZero {
		wipeBytes(c2)
		return "", errors.New("decryption verification failed")
	}
	return bytesAsString(c2), nil
}

// SM2Sign signs a message with userID and private key. The signature is the lowercase
// hex of r, then "h", then the lowercase hex of s.
func SM2Sign(userID, message, privateKey string) (string, error) {
	if len(userID) > sm2MaxUserIDBytes {
		return "", errUserIDTooLong
	}
	d, err := parsePrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	defer wipeLimbs(&d.limbs)
	for i := 0; i < sm2MaxAttempts; i++ {
		k, err := randomScalar()
		if err != nil {
			return "", err
		}
		sig, ok := sm2SignWithNonce(userID, message, &d, &k)
		wipeLimbs(&k.limbs)
		if ok {
			return sig, nil
		}
	}
	return "", errRandom
}

// sm2ComputeR returns (e + x) mod n, with both reduced first, as GB/T 32918 defines it.
func sm2ComputeR(e, x *BigInt256) BigInt256 {
	reducedE := BigInt256{limbs: scalarReduce(&e.limbs)}
	reducedX := BigInt256{limbs: scalarReduce(&x.limbs)}
	n := BigInt256{limbs: curveN}
	return reducedE.ModAdd(&reducedX, &n)
}

// sm2SignWithNonce signs with the nonce k and reports false if k must be replaced. d must
// be in [1, n-2] and k in [1, n-1].
func sm2SignWithNonce(userID, message string, d, k *BigInt256) (string, bool) {
	pubJac := sm2BaseMult(d)
	kJac := sm2BaseMult(k)
	pub, kp := pairToAffine(&pubJac, &kJac)

	e := sm2MessageDigest(userID, message, &pub)
	r := sm2ComputeR(&e, &kp.X.value)
	if r.IsZero() {
		return "", false
	}
	rk, _ := r.Add(k)
	if limbsEqual(&rk.limbs, &curveN) {
		return "", false
	}

	// s = (1 + d)^-1 * (k - r*d) mod n
	n := BigInt256{limbs: curveN}
	dPlus1, _ := d.Add(&bigOne)
	var dPlus1Inv, rd, s BigInt256
	scalarInvert(&dPlus1Inv.limbs, &dPlus1.limbs)
	scalarMul(&rd.limbs, &r.limbs, &d.limbs)
	kMinusRD := k.ModSub(&rd, &n)
	scalarMul(&s.limbs, &kMinusRD.limbs, &dPlus1Inv.limbs)
	defer wipeLimbs(&dPlus1.limbs)
	defer wipeLimbs(&dPlus1Inv.limbs)
	defer wipeLimbs(&rd.limbs)
	defer wipeLimbs(&kMinusRD.limbs)
	if s.IsZero() {
		return "", false
	}

	var raw [32]byte
	out := make([]byte, sm2SignatureHexLen)
	putLimbsBE(&raw, &r.limbs)
	encodeHexTo(out[:64], raw[:], lowerHex)
	out[64] = 'h'
	putLimbsBE(&raw, &s.limbs)
	encodeHexTo(out[65:], raw[:], lowerHex)
	return bytesAsString(out), true
}

// parseSignature reads the exact format of SM2Sign: 64 hex digits, "h", 64 hex digits,
// with r and s each in [1, n-1].
func parseSignature(signature string) (r, s BigInt256, ok bool) {
	if len(signature) != sm2SignatureHexLen || signature[64] != 'h' {
		return r, s, false
	}
	var rawR, rawS [32]byte
	if !decodeHexInto(rawR[:], signature[:64]) || !decodeHexInto(rawS[:], signature[65:]) {
		return r, s, false
	}
	r, s = BigInt256FromBEBytes(rawR[:]), BigInt256FromBEBytes(rawS[:])
	return r, s, scalarInRange(&r.limbs) && scalarInRange(&s.limbs)
}

// SM2Verify verifies a signature. Any invalid input gives false.
func SM2Verify(userID, signature, message, publicKey string) bool {
	if len(userID) > sm2MaxUserIDBytes {
		return false
	}
	r, s, ok := parseSignature(signature)
	if !ok {
		return false
	}
	pubPoint, ok := parseHexPoint(publicKey)
	if !ok {
		return false
	}

	e := sm2MessageDigest(userID, message, &pubPoint)

	n := BigInt256{limbs: curveN}
	t := r.ModAdd(&s, &n)
	if t.IsZero() {
		return false
	}

	var sum jacPoint
	jp := jacFromAffinePoint(&pubPoint)
	jacDoubleScalarMultVar(&sum, &s.limbs, &t.limbs, &jp)
	if feIsZeroMask(&sum.z) != 0 {
		return false
	}
	return verifyCheckR(&sum, &e, &r)
}

// verifyCheckR reports whether r == (e + x) mod n for the finite point p = (x, ...), with
// r in [1, n-1]. It avoids a field inversion by comparing X with x'*Z^2 for each
// candidate x', which are r - e mod n and that value plus n if it is still below p.
func verifyCheckR(p *jacPoint, e, r *BigInt256) bool {
	n := BigInt256{limbs: curveN}
	reducedE := BigInt256{limbs: scalarReduce(&e.limbs)}
	var zz fe
	feSqr(&zz, &p.z)
	candidate := r.ModSub(&reducedE, &n)
	if projectiveXEquals(p, &zz, &candidate) {
		return true
	}
	second, carry := candidate.Add(&n)
	return carry == 0 && limbsBelowP(&second.limbs) && projectiveXEquals(p, &zz, &second)
}

func projectiveXEquals(p *jacPoint, zz *fe, x *BigInt256) bool {
	var m fe
	feToMont(&m, &x.limbs)
	feMul(&m, &m, zz)
	return m == p.x
}

// keyExchangeInputsValid checks everything both sides of the key exchange receive.
func keyExchangeInputsValid(byteLen int, idA, idB string, points []*ECPoint, secrets []*BigInt256) string {
	if byteLen < 1 || byteLen > sm2MaxKeyExchangeBytes {
		return "invalid key length"
	}
	if len(idA) > sm2MaxUserIDBytes || len(idB) > sm2MaxUserIDBytes {
		return "user ID too long"
	}
	for _, p := range points {
		if !p.IsOnCurve() {
			return "invalid public point"
		}
	}
	for _, k := range secrets {
		if k == nil || !privateKeyInRange(&k.limbs) {
			return "invalid private key"
		}
	}
	return ""
}

// SM2GetSb computes B's key exchange parameters. All points must be valid curve points
// and dB and rb in [1, n-2]; otherwise Success is false and Message says what was wrong.
func SM2GetSb(byteLen int, pA, rA, pB ECPoint, dB *BigInt256, rB ECPoint, rb *BigInt256, idA, idB string) SM2KeySwapParams {
	result := SM2KeySwapParams{}
	if msg := keyExchangeInputsValid(byteLen, idA, idB, []*ECPoint{&pA, &rA, &pB, &rB}, []*BigInt256{dB, rb}); msg != "" {
		result.Message = msg
		return result
	}

	x2Bar := calcXBar(&rB.X.value)
	tb := calcT(rb, dB, &x2Bar)
	defer wipeLimbs(&tb.limbs)

	x1Bar := calcXBar(&rA.X.value)
	v := calcSharedPoint(&tb, &x1Bar, &pA, &rA)
	if v.Infinity {
		result.Message = "V is point at infinity"
		return result
	}

	za := sm2Z(stringAsBytes(idA), &pA)
	zb := sm2Z(stringAsBytes(idB), &pB)

	kb := kdfKeySwap(byteLen, &v, za[:], zb[:])
	sb := createS(0x02, &v, za[:], zb[:], &rA, &rB)

	result.Sb = bytesToHex(sb[:])
	result.Kb = bytesToHex(kb)
	wipeBytes(kb)
	result.V = &v
	result.Za = za[:]
	result.Zb = zb[:]
	result.Success = true
	return result
}

// SM2GetSa computes A's key exchange parameters. All points must be valid curve points
// and dA and ra in [1, n-2]; otherwise Success is false and Message says what was wrong.
func SM2GetSa(byteLen int, pB, rB, pA ECPoint, dA *BigInt256, rA ECPoint, ra *BigInt256, idA, idB string, sb []byte) SM2KeySwapParams {
	result := SM2KeySwapParams{}
	if msg := keyExchangeInputsValid(byteLen, idA, idB, []*ECPoint{&pB, &rB, &pA, &rA}, []*BigInt256{dA, ra}); msg != "" {
		result.Message = msg
		return result
	}

	x1Bar := calcXBar(&rA.X.value)
	ta := calcT(ra, dA, &x1Bar)
	defer wipeLimbs(&ta.limbs)

	x2Bar := calcXBar(&rB.X.value)
	u := calcSharedPoint(&ta, &x2Bar, &pB, &rB)
	if u.Infinity {
		result.Message = "U is point at infinity"
		return result
	}

	za := sm2Z(stringAsBytes(idA), &pA)
	zb := sm2Z(stringAsBytes(idB), &pB)

	s1 := createS(0x02, &u, za[:], zb[:], &rA, &rB)
	if !bytesEqual(s1[:], sb) {
		result.Message = "B's verification value does not match"
		return result
	}

	ka := kdfKeySwap(byteLen, &u, za[:], zb[:])
	sa := createS(0x03, &u, za[:], zb[:], &rA, &rB)
	result.Sa = bytesToHex(sa[:])
	result.Ka = bytesToHex(ka)
	wipeBytes(ka)
	result.Success = true
	return result
}

// SM2CheckSa verifies A's key exchange value Sa. Any invalid input gives false.
func SM2CheckSa(v ECPoint, za, zb []byte, rA, rB ECPoint, sa []byte) bool {
	if len(za) != 32 || len(zb) != 32 || len(sa) != 32 {
		return false
	}
	if !v.IsOnCurve() || !rA.IsOnCurve() || !rB.IsOnCurve() {
		return false
	}
	s2 := createS(0x03, &v, za, zb, &rA, &rB)
	return bytesEqual(s2[:], sa)
}

// SM2DecodePoint decodes a public key hex string to an ECPoint. This signature cannot
// report failure, so invalid input gives the point at infinity, which every key operation
// rejects. Use SM2ParsePublicKey to get an error instead.
func SM2DecodePoint(hexStr string) ECPoint {
	return ECPointFromHexEncoded(hexStr)
}

// SM2GetPublicKey computes the public key from a private key. It returns the point at
// infinity for a private key outside [1, n-2].
func SM2GetPublicKey(privateKey *BigInt256) ECPoint {
	if privateKey == nil || !privateKeyInRange(&privateKey.limbs) {
		return ECPointInfinity()
	}
	r := sm2BaseMult(privateKey)
	return r.toAffinePoint()
}

// --- internal helpers ---

// wipeLimbs overwrites a secret value, on a best-effort basis; see wipeBytes.
func wipeLimbs(l *[4]uint64) {
	*l = [4]uint64{}
	runtime.KeepAlive(l)
}

// readRandomBigInt fills r with 32 bytes from the OS CSPRNG, or returns an error.
func readRandomBigInt(r *BigInt256) error {
	var b [32]byte
	if _, err := io.ReadFull(sm2RandReader, b[:]); err != nil {
		return errRandom
	}
	*r = BigInt256FromBEBytes(b[:])
	wipeBytes(b[:])
	return nil
}

// randomScalar returns a uniformly random value in [1, n-1], using rejection sampling
// with a constant-time range check, a bounded number of times.
func randomScalar() (BigInt256, error) {
	for i := 0; i < sm2MaxAttempts; i++ {
		var k BigInt256
		if err := readRandomBigInt(&k); err != nil {
			return BigInt256{}, err
		}
		if scalarInRange(&k.limbs) {
			return k, nil
		}
	}
	return BigInt256{}, errRandom
}

// kdfXOR sets dst to src XOR the SM3 KDF stream for seed and reports whether the
// stream was all zeros. dst and src must have the same length, may be the same slice,
// and are at most sm2MaxKDFBytes long, so the 32-bit counter cannot wrap.
//
// The state after the whole blocks of seed is reused for every counter value.
func kdfXOR(dst, src, seed []byte) (allZero bool) {
	base := newSM3State()
	base.Update(seed)

	var accumulated byte
	var digest [32]byte
	var counter [4]byte
	for ct, off := uint32(1), 0; off < len(dst); ct, off = ct+1, off+32 {
		h := base
		binary.BigEndian.PutUint32(counter[:], ct)
		h.Update(counter[:])
		h.sum(&digest)
		wipeBytes(h.buff[:])
		n := subtle.XORBytes(dst[off:], src[off:], digest[:])
		for _, b := range digest[:n] {
			accumulated |= b
		}
	}
	wipeBytes(digest[:])
	wipeBytes(base.buff[:])
	return accumulated == 0
}

func kdfKeySwap(keylen int, vu *ECPoint, za, zb []byte) []byte {
	seed := make([]byte, 0, 64+len(za)+len(zb))
	var point [65]byte
	vu.encodeTo(&point)
	seed = append(seed, point[1:]...)
	seed = append(seed, za...)
	seed = append(seed, zb...)
	wipeBytes(point[:])

	key := make([]byte, keylen)
	kdfXOR(key, key, seed)
	wipeBytes(seed)
	return key
}

// sm2CurveParams is a||b||Gx||Gy, the fixed middle of the Z value.
var sm2CurveParams = func() [128]byte {
	var out [128]byte
	a := [4]uint64{p0 - 3, p1, p2, p3}
	b := [4]uint64{0xDDBCBD414D940E93, 0xF39789F515AB8F92, 0x4D5A9E4BCF6509A7, 0x28E9FA9E9D9F5E34}
	putLimbsBE((*[32]byte)(out[0:32]), &a)
	putLimbsBE((*[32]byte)(out[32:64]), &b)
	putLimbsBE((*[32]byte)(out[64:96]), &curveGX)
	putLimbsBE((*[32]byte)(out[96:128]), &curveGY)
	return out
}()

// sm2Z computes Z = SM3(ENTL || ID || a || b || Gx || Gy || x || y). Callers have checked
// the ID against sm2MaxUserIDBytes, so ENTL cannot wrap.
func sm2Z(userID []byte, publicKey *ECPoint) [32]byte {
	h := newSM3State()
	entl := uint16(len(userID) * 8)
	h.UpdateByte(byte(entl >> 8))
	h.UpdateByte(byte(entl))
	h.Update(userID)
	h.Update(sm2CurveParams[:])

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
	h := newSM3State()
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

// calcT computes (d + xBar*r) mod n, with d and r below n. d and r are secret.
func calcT(r, d, xBar *BigInt256) BigInt256 {
	n := BigInt256{limbs: curveN}
	var xr BigInt256
	scalarMul(&xr.limbs, &xBar.limbs, &r.limbs)
	t := d.ModAdd(&xr, &n)
	wipeLimbs(&xr.limbs)
	return t
}

// calcSharedPoint computes [t](p + [xBar]r). p and r are validated public points, and
// xBar is public, so the inner multiplication may be variable time; the outer one uses
// the secret t and is not.
func calcSharedPoint(t, xBar *BigInt256, p, r *ECPoint) ECPoint {
	var sum jacPoint
	jr := jacFromAffinePoint(r)
	jacScalarMultVar(&sum, &jr, &xBar.limbs)
	jp := jacFromAffinePoint(p)
	jacAddVar(&sum, &sum, &jp)
	if feIsZeroMask(&sum.z) != 0 {
		return ECPointInfinity()
	}
	scalar := scalarReduce(&t.limbs)
	var result jacPoint
	jacScalarMult(&result, &sum, &scalar)
	wipeLimbs(&scalar)
	return result.toAffinePoint()
}

func createS(tag byte, vu *ECPoint, za, zb []byte, ra, rb *ECPoint) [32]byte {
	var v, a, b [65]byte
	vu.encodeTo(&v)
	ra.encodeTo(&a)
	rb.encodeTo(&b)

	h := newSM3State()
	h.Update(v[1:33])
	h.Update(za)
	h.Update(zb)
	h.Update(a[1:])
	h.Update(b[1:])
	var inner [32]byte
	h.sum(&inner)

	outer := newSM3State()
	outer.UpdateByte(tag)
	outer.Update(v[33:])
	outer.Update(inner[:])
	var out [32]byte
	outer.sum(&out)
	wipeBytes(v[:])
	return out
}

// bytesEqual compares in constant time for inputs of equal length.
func bytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
