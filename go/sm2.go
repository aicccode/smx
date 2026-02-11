package smx

import (
	"crypto/rand"
	"fmt"
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

// SM2GenKeyPair generates a new SM2 key pair.
// Returns (privateKeyHex, publicKeyHex).
func SM2GenKeyPair() (string, string) {
	for {
		privateKey := randomBigInt()
		if privateKey.IsZero() || privateKey.Compare(&SM2_N) >= 0 {
			continue
		}
		publicKey := ECPointGenerator().Multiply(&privateKey)
		priHex := privateKey.ToHex()
		pubHex := publicKey.ToHexEncoded()
		if len(priHex) == 64 && len(pubHex) == 130 {
			return priHex, pubHex
		}
	}
}

// SM2Encrypt encrypts plaintext using the public key.
func SM2Encrypt(plaintext, publicKey string) (string, error) {
	message := []byte(plaintext)
	if len(message) == 0 {
		return "", fmt.Errorf("plaintext cannot be empty")
	}

	pubPoint := ECPointFromHexEncoded(publicKey)
	if !pubPoint.IsOnCurve() {
		return "", fmt.Errorf("invalid public key")
	}

	for {
		k := randomBigInt()
		if k.IsZero() || k.Compare(&SM2_N) >= 0 {
			continue
		}

		c1 := ECPointGenerator().Multiply(&k)
		p2 := pubPoint.Multiply(&k)
		if p2.Infinity {
			continue
		}

		key := kdf(len(message), p2)
		allZero := true
		for _, b := range key {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			continue
		}

		c2 := make([]byte, len(message))
		for i := range message {
			c2[i] = message[i] ^ key[i]
		}

		sm3 := NewSM3()
		x2b := p2.X.ToBEBytes()
		y2b := p2.Y.ToBEBytes()
		sm3.Update(x2b[:])
		sm3.Update(message)
		sm3.Update(y2b[:])
		sm3.Finish()
		c3 := sm3.HashBytes()

		result := c1.ToHexEncoded() + bytesToHex(c3[:]) + bytesToHex(c2)
		return result, nil
	}
}

// SM2Decrypt decrypts ciphertext using the private key.
func SM2Decrypt(ciphertext, privateKey string) (string, error) {
	if len(ciphertext) < 130+64 {
		return "", fmt.Errorf("ciphertext too short")
	}

	c1Hex := ciphertext[:130]
	c3Hex := ciphertext[130:194]
	c2Hex := ciphertext[194:]

	c1 := ECPointFromHexEncoded(c1Hex)
	if !c1.IsOnCurve() {
		return "", fmt.Errorf("invalid C1 point")
	}

	c3, err := hexToBytes(c3Hex)
	if err != nil {
		return "", fmt.Errorf("invalid C3 hex")
	}
	c2, err := hexToBytes(c2Hex)
	if err != nil {
		return "", fmt.Errorf("invalid C2 hex")
	}

	d := BigInt256FromHex(privateKey)
	p2 := c1.Multiply(&d)
	if p2.Infinity {
		return "", fmt.Errorf("invalid decryption")
	}

	key := kdf(len(c2), p2)
	for i := range c2 {
		c2[i] ^= key[i]
	}

	sm3 := NewSM3()
	x2b := p2.X.ToBEBytes()
	y2b := p2.Y.ToBEBytes()
	sm3.Update(x2b[:])
	sm3.Update(c2)
	sm3.Update(y2b[:])
	sm3.Finish()
	computedC3 := sm3.HashBytes()

	if !bytesEqual(computedC3[:], c3) {
		return "", fmt.Errorf("decryption verification failed")
	}

	return string(c2), nil
}

// SM2Sign signs a message with userID and private key.
func SM2Sign(userID, message, privateKey string) (string, error) {
	d := BigInt256FromHex(privateKey)
	publicKey := ECPointGenerator().Multiply(&d)

	z := userSM3Z([]byte(userID), publicKey)

	sm3 := NewSM3()
	sm3.Update(z)
	sm3.Update([]byte(message))
	sm3.Finish()
	eBytes := sm3.HashBytes()
	e := BigInt256FromBEBytes(eBytes[:])

	for {
		k := randomBigInt()
		if k.IsZero() || k.Compare(&SM2_N) >= 0 {
			continue
		}

		kp := ECPointGenerator().Multiply(&k)
		x1 := kp.X.ToBigInt()

		r := e.ModAdd(&x1, &SM2_N)
		if r.IsZero() {
			continue
		}

		rk, _ := r.Add(&k)
		if rk == SM2_N {
			continue
		}

		dPlus1, _ := d.Add(&bigOne)
		dPlus1Inv := dPlus1.ModInverse(&SM2_N)
		rd := r.ModMul(&d, &SM2_N)
		kMinusRD := k.ModSub(&rd, &SM2_N)
		s := kMinusRD.ModMul(&dPlus1Inv, &SM2_N)

		if s.IsZero() {
			continue
		}

		rHex := r.ToHex()
		sHex := s.ToHex()
		if len(rHex) == 64 && len(sHex) == 64 {
			return strings.ToLower(rHex) + "h" + strings.ToLower(sHex), nil
		}
	}
}

// SM2Verify verifies a signature.
func SM2Verify(userID, signature, message, publicKey string) bool {
	parts := strings.Split(signature, "h")
	if len(parts) != 2 {
		return false
	}

	r := BigInt256FromHex(parts[0])
	s := BigInt256FromHex(parts[1])

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

	z := userSM3Z([]byte(userID), pubPoint)

	sm3 := NewSM3()
	sm3.Update(z)
	sm3.Update([]byte(message))
	sm3.Finish()
	eBytes := sm3.HashBytes()
	e := BigInt256FromBEBytes(eBytes[:])

	t := r.ModAdd(&s, &SM2_N)
	if t.IsZero() {
		return false
	}

	sg := ECPointGenerator().Multiply(&s)
	tpa := pubPoint.Multiply(&t)
	point := sg.Add(tpa)

	if point.Infinity {
		return false
	}

	px := point.X.ToBigInt()
	computedR := e.ModAdd(&px, &SM2_N)
	return r == computedR
}

// SM2GetSb computes B's key exchange parameters.
func SM2GetSb(byteLen int, pA, rA, pB ECPoint, dB *BigInt256, rB ECPoint, rb *BigInt256, idA, idB string) SM2KeySwapParams {
	result := SM2KeySwapParams{}

	x2_ := calcX(rB.X.ToBigInt())
	tb := calcT(&SM2_N, rb, dB, &x2_)

	if !rA.IsOnCurve() {
		result.Message = "RA point is not on curve"
		return result
	}

	x1_ := calcX(rA.X.ToBigInt())
	v := calcPoint(&tb, &x1_, pA, rA)
	if v.Infinity {
		result.Message = "V is point at infinity"
		return result
	}

	za := userSM3Z([]byte(idA), pA)
	zb := userSM3Z([]byte(idB), pB)

	kb := kdfKeySwap(byteLen, v, za, zb)
	sb := createS(0x02, v, za, zb, rA, rB)

	result.Sb = bytesToHex(sb)
	result.Kb = bytesToHex(kb)
	result.V = &v
	result.Za = za
	result.Zb = zb
	result.Success = true
	return result
}

// SM2GetSa computes A's key exchange parameters.
func SM2GetSa(byteLen int, pB, rB, pA ECPoint, dA *BigInt256, rA ECPoint, ra *BigInt256, idA, idB string, sb []byte) SM2KeySwapParams {
	result := SM2KeySwapParams{}

	x1_ := calcX(rA.X.ToBigInt())
	ta := calcT(&SM2_N, ra, dA, &x1_)

	if !rB.IsOnCurve() {
		result.Message = "RB point is not on curve"
		return result
	}

	x2_ := calcX(rB.X.ToBigInt())
	u := calcPoint(&ta, &x2_, pB, rB)
	if u.Infinity {
		result.Message = "U is point at infinity"
		return result
	}

	za := userSM3Z([]byte(idA), pA)
	zb := userSM3Z([]byte(idB), pB)

	ka := kdfKeySwap(byteLen, u, za, zb)
	s1 := createS(0x02, u, za, zb, rA, rB)

	if !bytesEqual(s1, sb) {
		result.Message = "B's verification value does not match"
		return result
	}

	sa := createS(0x03, u, za, zb, rA, rB)
	result.Sa = bytesToHex(sa)
	result.Ka = bytesToHex(ka)
	result.Success = true
	return result
}

// SM2CheckSa verifies A's key exchange value Sa.
func SM2CheckSa(v ECPoint, za, zb []byte, rA, rB ECPoint, sa []byte) bool {
	s2 := createS(0x03, v, za, zb, rA, rB)
	return bytesEqual(s2, sa)
}

// SM2DecodePoint decodes a public key hex string to an ECPoint.
func SM2DecodePoint(hexStr string) ECPoint {
	return ECPointFromHexEncoded(hexStr)
}

// SM2GetPublicKey computes the public key from a private key.
func SM2GetPublicKey(privateKey *BigInt256) ECPoint {
	return ECPointGenerator().Multiply(privateKey)
}

// --- internal helpers ---

func randomBigInt() BigInt256 {
	var b [32]byte
	rand.Read(b[:])
	return BigInt256FromBEBytes(b[:])
}

func kdf(keylen int, p2 ECPoint) []byte {
	result := make([]byte, keylen)
	ct := uint32(1)
	blocks := (keylen + 31) / 32

	for i := 0; i < blocks; i++ {
		sm3 := NewSM3()
		x2b := p2.X.ToBEBytes()
		y2b := p2.Y.ToBEBytes()
		sm3.Update(x2b[:])
		sm3.Update(y2b[:])
		ctBytes := [4]byte{byte(ct >> 24), byte(ct >> 16), byte(ct >> 8), byte(ct)}
		sm3.Update(ctBytes[:])
		sm3.Finish()
		hash := sm3.HashBytes()

		start := i * 32
		end := (i + 1) * 32
		if end > keylen {
			end = keylen
		}
		copy(result[start:end], hash[:end-start])
		ct++
	}
	return result
}

func kdfKeySwap(keylen int, vu ECPoint, za, zb []byte) []byte {
	result := make([]byte, keylen)
	ct := uint32(1)
	blocks := (keylen + 31) / 32

	for i := 0; i < blocks; i++ {
		sm3 := NewSM3()
		xb := vu.X.ToBEBytes()
		yb := vu.Y.ToBEBytes()
		sm3.Update(xb[:])
		sm3.Update(yb[:])
		sm3.Update(za)
		sm3.Update(zb)
		ctBytes := [4]byte{byte(ct >> 24), byte(ct >> 16), byte(ct >> 8), byte(ct)}
		sm3.Update(ctBytes[:])
		sm3.Finish()
		hash := sm3.HashBytes()

		start := i * 32
		end := (i + 1) * 32
		if end > keylen {
			end = keylen
		}
		copy(result[start:end], hash[:end-start])
		ct++
	}
	return result
}

func userSM3Z(userID []byte, publicKey ECPoint) []byte {
	sm3 := NewSM3()

	entl := uint16(len(userID) * 8)
	sm3.UpdateByte(byte(entl >> 8))
	sm3.UpdateByte(byte(entl & 0xFF))

	sm3.Update(userID)

	ab := SM2_A.ToBEBytes()
	sm3.Update(ab[:])
	bb := SM2_B.ToBEBytes()
	sm3.Update(bb[:])
	gxb := SM2_GX.ToBEBytes()
	sm3.Update(gxb[:])
	gyb := SM2_GY.ToBEBytes()
	sm3.Update(gyb[:])
	xab := publicKey.X.ToBEBytes()
	sm3.Update(xab[:])
	yab := publicKey.Y.ToBEBytes()
	sm3.Update(yab[:])

	sm3.Finish()
	h := sm3.HashBytes()
	return h[:]
}

func calcX(x BigInt256) BigInt256 {
	twoPowW := BigInt256FromHex("80000000000000000000000000000000")
	mask := BigInt256FromHex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
	xMasked := x.And(&mask)
	result, _ := twoPowW.Add(&xMasked)
	return result
}

func calcT(n, r, d, x_ *BigInt256) BigInt256 {
	xr := x_.ModMul(r, n)
	return d.ModAdd(&xr, n)
}

func calcPoint(t, x_ *BigInt256, p, r ECPoint) ECPoint {
	xr := r.Multiply(x_)
	sum := p.Add(xr)
	return sum.Multiply(t)
}

func createS(tag byte, vu ECPoint, za, zb []byte, ra, rb ECPoint) []byte {
	sm3 := NewSM3()
	vxb := vu.X.ToBEBytes()
	sm3.Update(vxb[:])
	sm3.Update(za)
	sm3.Update(zb)
	raxb := ra.X.ToBEBytes()
	sm3.Update(raxb[:])
	rayb := ra.Y.ToBEBytes()
	sm3.Update(rayb[:])
	rbxb := rb.X.ToBEBytes()
	sm3.Update(rbxb[:])
	rbyb := rb.Y.ToBEBytes()
	sm3.Update(rbyb[:])
	sm3.Finish()
	h1 := sm3.HashBytes()

	hash := NewSM3()
	hash.UpdateByte(tag)
	vyb := vu.Y.ToBEBytes()
	hash.Update(vyb[:])
	hash.Update(h1[:])
	hash.Finish()
	h2 := hash.HashBytes()
	return h2[:]
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
