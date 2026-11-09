package smx

import (
	"encoding/hex"
	"math/big"
	"math/rand"
	"testing"
)

// Algebraic checks of the SM9 field tower, groups and pairing against math/big and
// against each other.

var (
	sm9BigQ = limbsToBig(sm9Q)
	sm9BigN = limbsToBig(sm9N)
)

func sm9RandFp(r *rand.Rand) sm9Fp {
	v := new(big.Int).Rand(r, sm9BigQ)
	var z sm9Fp
	l := bigToLimbs(v)
	sm9FpToMont(&z, &l)
	return z
}

func sm9FpBig(x *sm9Fp) *big.Int { return limbsToBig(sm9FpFromMont(x)) }

func sm9RandFp2(r *rand.Rand) sm9Fp2 { return sm9Fp2{sm9RandFp(r), sm9RandFp(r)} }

func sm9RandFp12(r *rand.Rand) sm9Fp12 {
	var z sm9Fp12
	for _, c := range z.coefs() {
		*c = sm9RandFp2(r)
	}
	return z
}

func sm9RandScalarTest(r *rand.Rand) [4]uint64 {
	v := new(big.Int).Rand(r, new(big.Int).Sub(sm9BigN, big.NewInt(1)))
	return bigToLimbs(v.Add(v, big.NewInt(1)))
}

// sm9Fp12MulSchool multiplies with the textbook w^6 = u reduction, as the reference does.
func sm9Fp12MulSchool(x, y *sm9Fp12) sm9Fp12 {
	cx, cy := x.coefs(), y.coefs()
	var acc [11]sm9Fp2
	for i := 0; i < 6; i++ {
		for j := 0; j < 6; j++ {
			var t sm9Fp2
			sm9Fp2Mul(&t, cx[i], cy[j])
			sm9Fp2Add(&acc[i+j], &acc[i+j], &t)
		}
	}
	var z sm9Fp12
	cz := z.coefs()
	for k := 0; k < 6; k++ {
		*cz[k] = acc[k]
		if k < 5 {
			var t sm9Fp2
			sm9Fp2MulU(&t, &acc[k+6])
			sm9Fp2Add(cz[k], cz[k], &t)
		}
	}
	return z
}

// sm9Fp12PowBig raises x to any non-negative exponent by square and multiply.
func sm9Fp12PowBig(x *sm9Fp12, e *big.Int) sm9Fp12 {
	z := sm9Fp12One()
	for i := e.BitLen() - 1; i >= 0; i-- {
		sm9Fp12Mul(&z, &z, &z)
		if e.Bit(i) == 1 {
			sm9Fp12Mul(&z, &z, x)
		}
	}
	return z
}

func TestSM9FpAgainstBig(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	edge := []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(sm9BigQ, big.NewInt(1)), new(big.Int).Rsh(sm9BigQ, 1)}
	for i := 0; i < 2000; i++ {
		var a, b sm9Fp
		if i < len(edge)*len(edge) {
			la, lb := bigToLimbs(edge[i%len(edge)]), bigToLimbs(edge[i/len(edge)])
			sm9FpToMont(&a, &la)
			sm9FpToMont(&b, &lb)
		} else {
			a, b = sm9RandFp(r), sm9RandFp(r)
		}
		ab, bb := sm9FpBig(&a), sm9FpBig(&b)
		var z sm9Fp
		check := func(op string, want *big.Int) {
			t.Helper()
			want.Mod(want, sm9BigQ)
			if sm9FpBig(&z).Cmp(want) != 0 {
				t.Fatalf("%s(%x, %x) wrong", op, ab, bb)
			}
		}
		sm9FpMul(&z, &a, &b)
		check("mul", new(big.Int).Mul(ab, bb))
		sm9FpSqr(&z, &a)
		check("sqr", new(big.Int).Mul(ab, ab))
		sm9FpAdd(&z, &a, &b)
		check("add", new(big.Int).Add(ab, bb))
		sm9FpSub(&z, &a, &b)
		check("sub", new(big.Int).Sub(ab, bb))
		sm9FpNeg(&z, &a)
		check("neg", new(big.Int).Neg(ab))
		sm9FpInv(&z, &a)
		if ab.Sign() == 0 {
			check("inv", big.NewInt(0))
		} else {
			check("inv", new(big.Int).ModInverse(ab, sm9BigQ))
		}
	}
}

func TestSM9ScalarAgainstBig(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 1000; i++ {
		a, b := sm9RandScalarTest(r), sm9RandScalarTest(r)
		ab, bb := limbsToBig(a), limbsToBig(b)
		var z [4]uint64
		sm9NMul(&z, &a, &b)
		if limbsToBig(z).Cmp(new(big.Int).Mod(new(big.Int).Mul(ab, bb), sm9BigN)) != 0 {
			t.Fatal("mul")
		}
		sm9NInv(&z, &a)
		if limbsToBig(z).Cmp(new(big.Int).ModInverse(ab, sm9BigN)) != 0 {
			t.Fatal("inv")
		}
		sm9NSub(&z, &a, &b)
		if limbsToBig(z).Cmp(new(big.Int).Mod(new(big.Int).Sub(ab, bb), sm9BigN)) != 0 {
			t.Fatal("sub")
		}
		var ha [40]byte
		r.Read(ha[:])
		if i == 0 {
			for j := range ha {
				ha[j] = 0xFF
			}
		}
		want := new(big.Int).SetBytes(ha[:])
		want.Mod(want, new(big.Int).Sub(sm9BigN, big.NewInt(1))).Add(want, big.NewInt(1))
		if got := sm9HashReduce(&ha); limbsToBig(got).Cmp(want) != 0 {
			t.Fatalf("hash reduce %x", ha)
		}
	}
	var zero [4]uint64
	sm9NInv(&zero, &zero)
	if !sm9IsZero(&zero) {
		t.Fatal("inverse of zero")
	}
	n := sm9N
	nm1 := sm9NMinus1
	if sm9NInRange(&n) || !sm9NInRange(&nm1) || sm9NInRange(&[4]uint64{}) {
		t.Fatal("range check")
	}
}

func TestSM9TowerIdentities(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	one := sm9Fp12One()
	for i := 0; i < 50; i++ {
		x, y := sm9RandFp12(r), sm9RandFp12(r)
		var z, w sm9Fp12
		sm9Fp12Mul(&z, &x, &y)
		if z != sm9Fp12MulSchool(&x, &y) {
			t.Fatal("Fp12 mul disagrees with the schoolbook product")
		}
		sm9Fp12Sqr(&z, &x)
		if z != sm9Fp12MulSchool(&x, &x) {
			t.Fatal("Fp12 sqr")
		}
		sm9Fp12Inv(&z, &x)
		sm9Fp12Mul(&w, &z, &x)
		if w != one {
			t.Fatal("Fp12 inverse")
		}

		// Sparse line multiplication.
		l0, l1, l4 := sm9RandFp2(r), sm9RandFp2(r), sm9RandFp2(r)
		var line sm9Fp12
		line.c0.b0, line.c0.b1, line.c1.b1 = l0, l1, l4
		z = x
		sm9Fp12MulBy014(&z, &l0, &l1, &l4)
		if z != sm9Fp12MulSchool(&x, &line) {
			t.Fatal("MulBy014")
		}

		// Frobenius against exponentiation by q.
		if i < 3 {
			q := sm9BigQ
			sm9Fp12Frob(&z, &x, 1)
			if z != sm9Fp12PowBig(&x, q) {
				t.Fatal("Frobenius q")
			}
			sm9Fp12Frob(&w, &z, 1)
			sm9Fp12Frob(&z, &x, 2)
			if z != w {
				t.Fatal("Frobenius q^2")
			}
			sm9Fp12Frob(&w, &w, 1)
			sm9Fp12Frob(&z, &x, 3)
			if z != w {
				t.Fatal("Frobenius q^3")
			}
			var c sm9Fp12
			sm9Fp12Frob(&w, &z, 3)
			sm9Fp12Conj(&c, &x)
			if w != c {
				t.Fatal("conjugation is not q^6")
			}
		}

		// Cyclotomic squaring on x^((q^6-1)(q^2+1)).
		var c, g sm9Fp12
		sm9Fp12Conj(&c, &x)
		sm9Fp12Inv(&z, &x)
		sm9Fp12Mul(&g, &c, &z)
		sm9Fp12Frob(&z, &g, 2)
		sm9Fp12Mul(&g, &z, &g)
		sm9Fp12CycSqr(&z, &g)
		sm9Fp12Sqr(&w, &g)
		if z != w {
			t.Fatal("cyclotomic squaring")
		}
		if i < 5 {
			k := sm9RandScalarTest(r)
			sm9GTExp(&z, &g, &k)
			if z != sm9Fp12PowBig(&g, limbsToBig(k)) {
				t.Fatal("GT exponentiation")
			}
		}
	}
}

func TestSM9FinalExpExact(t *testing.T) {
	r := rand.New(rand.NewSource(4))
	x := sm9RandFp12(r)
	e := new(big.Int).Exp(sm9BigQ, big.NewInt(12), nil)
	e.Sub(e, big.NewInt(1)).Div(e, sm9BigN)
	if sm9FinalExp(&x) != sm9Fp12PowBig(&x, e) {
		t.Fatal("final exponentiation is not x^((q^12-1)/N)")
	}
}

func TestSM9GroupsAndBilinearity(t *testing.T) {
	r := rand.New(rand.NewSource(5))
	if !sm9P1.onCurve() || !sm9P2.onCurve() || !sm9P2.inSubgroup() {
		t.Fatal("generators")
	}
	nm1 := sm9NMinus1
	for i := 0; i < 6; i++ {
		a, b := sm9RandScalarTest(r), sm9RandScalarTest(r)
		if i == 0 {
			a = nm1 // the doubling case in the last window of the ladder
		}
		pa, ok := sm9G1Mul(&sm9P1, &a)
		qb, ok2 := sm9G2Mul(&sm9P2, &b)
		if !ok || !ok2 || !pa.onCurve() || !qb.onCurve() || !qb.inSubgroup() {
			t.Fatal("scalar multiplication left the group")
		}
		var vj sm9G1Jac
		p1 := sm9P1.jac()
		sm9G1ScalarMultVar(&vj, &p1, &a)
		if v, _ := vj.toAffine(); v != pa {
			t.Fatal("G1 constant-time and variable-time disagree")
		}
		var wj sm9G2Jac
		p2 := sm9P2.jac()
		sm9G2ScalarMultVar(&wj, &p2, &b)
		if w, _ := wj.toAffine(); w != qb {
			t.Fatal("G2 constant-time and variable-time disagree")
		}
		var ab [4]uint64
		sm9NMul(&ab, &a, &b)
		lhs := sm9Pair(&pa, &qb)
		base := sm9Pair(&sm9P1, &sm9P2)
		var rhs sm9Fp12
		sm9GTExp(&rhs, &base, &ab)
		if lhs != rhs {
			t.Fatal("e([a]P1, [b]P2) != e(P1, P2)^(ab)")
		}
	}
	// [N-1]P == -P, and [N]P is the identity.
	n := sm9N
	var j sm9G1Jac
	p1 := sm9P1.jac()
	sm9G1ScalarMultVar(&j, &p1, &n)
	if !j.isInfinity() {
		t.Fatal("[N]P1 is not the identity")
	}
	neg, _ := sm9G1Mul(&sm9P1, &nm1)
	var y sm9Fp
	sm9FpNeg(&y, &sm9P1.y)
	if neg.x != sm9P1.x || neg.y != y {
		t.Fatal("[N-1]P1 != -P1")
	}
	// The identity in the ladder.
	var inf sm9G1Jac
	k := [4]uint64{5}
	sm9G1ScalarMult(&j, &inf, &k)
	if !j.isInfinity() {
		t.Fatal("[k]O")
	}
}

// TestSM9SubgroupCheck: multiples of the non-subgroup point of the vectors stay outside
// G2 unless the multiplier kills the G2-free part, and sums with G2 points stay outside.
func TestSM9SubgroupCheck(t *testing.T) {
	v := loadSM9Vectors(t)
	var bad string
	for _, p := range v.InvalidPoints.G2 {
		if p.Name == "not_in_subgroup" {
			bad = p.Value
		}
	}
	raw, _ := hex.DecodeString(bad)
	var p sm9G2Aff
	sm9FpSetBytes(&p.x.a1, raw[1:33])
	sm9FpSetBytes(&p.x.a0, raw[33:65])
	sm9FpSetBytes(&p.y.a1, raw[65:97])
	sm9FpSetBytes(&p.y.a0, raw[97:129])
	if !p.onCurve() || p.inSubgroup() {
		t.Fatal("vector point should be on the twist and outside G2")
	}
	if _, ok := sm9G2FromBytes(raw); ok {
		t.Fatal("decoder accepted a point outside G2")
	}
	pj, p2 := p.jac(), sm9P2.jac()
	var sum sm9G2Jac
	sm9G2AddVar(&sum, &pj, &p2)
	if s, ok := sum.toAffine(); !ok || s.inSubgroup() {
		t.Fatal("P + P2 should be outside G2")
	}
}

func TestSM9HashVectors(t *testing.T) {
	// H1("Alice" || 01) from GB/T 38635.5 appendix A.
	h := sm9H1([]byte("Alice"), 1)
	want := "2acc468c3926b0bdb2767e99ff26e084de9ced8dbc7d5fbf418027b667862fab"
	if got := hex.EncodeToString(func() []byte { b := BigInt256{limbs: h}.ToBEBytes(); return b[:] }()); got != want {
		t.Fatalf("H1 = %s", got)
	}
}
