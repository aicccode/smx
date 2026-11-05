package smx

import (
	"math/big"
	"math/rand"
	"testing"
)

// A deliberately naive affine implementation of the curve over math/big, independent
// of the limb arithmetic, as the reference for the group operations.

type refPoint struct {
	x, y *big.Int // nil x means infinity
}

var (
	refA = new(big.Int).Sub(bigP, big.NewInt(3))
	refG = refPoint{limbsToBig(SM2_GX.value.limbs), limbsToBig(SM2_GY.value.limbs)}
)

func refAdd(p, q refPoint) refPoint {
	if p.x == nil {
		return q
	}
	if q.x == nil {
		return p
	}
	var slope *big.Int
	if p.x.Cmp(q.x) == 0 {
		if new(big.Int).Mod(new(big.Int).Add(p.y, q.y), bigP).Sign() == 0 {
			return refPoint{}
		}
		num := new(big.Int).Mul(p.x, p.x)
		num.Mul(num, big.NewInt(3)).Add(num, refA)
		den := new(big.Int).ModInverse(new(big.Int).Lsh(p.y, 1), bigP)
		slope = num.Mul(num, den)
	} else {
		den := new(big.Int).Sub(q.x, p.x)
		den.Mod(den, bigP).ModInverse(den, bigP)
		slope = new(big.Int).Sub(q.y, p.y)
		slope.Mul(slope, den)
	}
	slope.Mod(slope, bigP)
	x := new(big.Int).Mul(slope, slope)
	x.Sub(x, p.x).Sub(x, q.x).Mod(x, bigP)
	y := new(big.Int).Sub(p.x, x)
	y.Mul(y, slope).Sub(y, p.y).Mod(y, bigP)
	return refPoint{x, y}
}

func refMul(p refPoint, k *big.Int) refPoint {
	r := refPoint{}
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = refAdd(r, r)
		if k.Bit(i) == 1 {
			r = refAdd(r, p)
		}
	}
	return r
}

func refToEC(p refPoint) ECPoint {
	if p.x == nil {
		return ECPointInfinity()
	}
	return NewECPoint(FpElement{BigInt256{limbs: bigToLimbs(p.x)}}, FpElement{BigInt256{limbs: bigToLimbs(p.y)}})
}

func checkPoint(t *testing.T, op string, got ECPoint, want refPoint) {
	t.Helper()
	if !got.Equal(refToEC(want)) {
		t.Fatalf("%s = %s, want %s", op, got.ToHexEncoded(), refToEC(want).ToHexEncoded())
	}
	if !got.IsOnCurve() {
		t.Fatalf("%s is off the curve", op)
	}
}

func TestReferenceCurve(t *testing.T) {
	if p := refMul(refG, bigN); p.x != nil {
		t.Fatal("[n]G is not infinity in the reference")
	}
}

// edgeScalars covers small values, values around n, and window boundaries.
func edgeScalars(rng *rand.Rand, random int) []*big.Int {
	values := edgeValues()
	for _, shift := range []uint{5, 6, 10, 30, 64, 127, 128, 192, 250, 251, 252, 254, 255} {
		s := new(big.Int).Lsh(big.NewInt(1), shift)
		for _, d := range []int64{-33, -32, -31, -17, -16, -15, -1, 0, 1, 15, 16, 17, 31, 32, 33} {
			if v := new(big.Int).Add(s, big.NewInt(d)); v.Sign() >= 0 {
				values = append(values, v)
			}
		}
	}
	return append(values, diffValues(rng, random)...)
}

func TestMultiplyDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	d := new(big.Int).SetBytes(hexMust(benchPrivateKey))
	refP := refMul(refG, d)
	p := refToEC(refP)
	g := ECPointGenerator()

	scalars := edgeScalars(rng, 40)
	if testing.Short() {
		scalars = scalars[:40]
	}
	for _, k := range scalars {
		scalar := BigInt256{limbs: bigToLimbs(k)}
		reduced := new(big.Int).Mod(k, bigN)
		checkPoint(t, "[k]G", g.Multiply(&scalar), refMul(refG, reduced))
		checkPoint(t, "[k]P", p.Multiply(&scalar), refMul(refP, reduced))
		checkPoint(t, "SM2GetPublicKey", SM2GetPublicKey(&scalar), refMul(refG, reduced))
	}
}

// Near-exhaustive check at both ends of the scalar range, where the exceptional cases
// of the addition formulas live. In particular k = n - 6 reaches the doubling case in
// the last window of the variable-base loop.
func TestMultiplyScalarExtremes(t *testing.T) {
	limit := int64(5000)
	if testing.Short() {
		limit = 200
	}
	d := new(big.Int).SetBytes(hexMust(benchPrivateKey))
	refP := refMul(refG, d)
	p := refToEC(refP)
	g := ECPointGenerator()

	wantG, wantP := refPoint{}, refPoint{}
	for i := int64(1); i <= limit; i++ {
		wantG = refAdd(wantG, refG)
		wantP = refAdd(wantP, refP)
		k := big.NewInt(i)
		nk := new(big.Int).Sub(bigN, k)
		small, large := BigInt256{limbs: bigToLimbs(k)}, BigInt256{limbs: bigToLimbs(nk)}

		checkPoint(t, "[i]G", g.Multiply(&small), wantG)
		checkPoint(t, "[i]P", p.Multiply(&small), wantP)
		negG := refPoint{wantG.x, new(big.Int).Sub(bigP, wantG.y)}
		negP := refPoint{wantP.x, new(big.Int).Sub(bigP, wantP.y)}
		if !g.Multiply(&large).Equal(refToEC(negG)) {
			t.Fatalf("[n-%d]G wrong", i)
		}
		if !p.Multiply(&large).Equal(refToEC(negP)) {
			t.Fatalf("[n-%d]P wrong", i)
		}
	}
}

func TestPointAdditionCases(t *testing.T) {
	rng := rand.New(rand.NewSource(12))
	g := ECPointGenerator()
	inf := ECPointInfinity()
	if !g.Add(inf).Equal(g) || !inf.Add(g).Equal(g) {
		t.Fatal("P + infinity")
	}
	if !inf.Add(inf).Infinity {
		t.Fatal("infinity + infinity")
	}
	if !g.Add(g.Negate()).Infinity {
		t.Fatal("P + (-P)")
	}
	if !g.Subtract(g).Infinity {
		t.Fatal("P - P")
	}
	if !inf.Twice().Infinity || !inf.Negate().Infinity || !inf.IsOnCurve() {
		t.Fatal("infinity identities")
	}
	if got := inf.ToHexEncoded(); got != "00" {
		t.Fatalf("infinity encoding %q", got)
	}
	for i := 0; i < 60; i++ {
		a := new(big.Int).Rand(rng, bigN)
		b := new(big.Int).Rand(rng, bigN)
		ra, rb := refMul(refG, a), refMul(refG, b)
		pa, pb := refToEC(ra), refToEC(rb)
		checkPoint(t, "Add", pa.Add(pb), refAdd(ra, rb))
		checkPoint(t, "Add same", pa.Add(pa), refAdd(ra, ra))
		checkPoint(t, "Twice", pa.Twice(), refAdd(ra, ra))
		checkPoint(t, "Subtract", pa.Subtract(pb), refAdd(ra, refPoint{rb.x, new(big.Int).Sub(bigP, rb.y)}))
	}
}

func TestDoubleScalarMultVar(t *testing.T) {
	rng := rand.New(rand.NewSource(13))
	d := new(big.Int).SetBytes(hexMust(benchPrivateKey))
	refP := refMul(refG, d)
	ecP := refToEC(refP)
	jp := jacFromAffinePoint(&ecP)
	g := ECPointGenerator()
	jg := jacFromAffinePoint(&g)

	scalars := edgeScalars(rng, 40)
	scalars = append(scalars, new(big.Int).Sub(bigN, big.NewInt(6)))
	for _, s := range scalars {
		s = new(big.Int).Mod(s, bigN)
		u := new(big.Int).Mod(scalars[rng.Intn(len(scalars))], bigN)
		ls, lu := bigToLimbs(s), bigToLimbs(u)
		want := refAdd(refMul(refG, s), refMul(refP, u))
		var r jacPoint
		jacDoubleScalarMultVar(&r, &ls, &lu, &jp)
		checkPoint(t, "[s]G+[t]P", r.toAffinePoint(), want)

		// With P == G the additions meet doubling and cancelling cases.
		want = refMul(refG, new(big.Int).Mod(new(big.Int).Add(s, u), bigN))
		jacDoubleScalarMultVar(&r, &ls, &lu, &jg)
		checkPoint(t, "[s]G+[t]G", r.toAffinePoint(), want)

		neg := new(big.Int).Sub(bigN, s)
		lneg := bigToLimbs(neg.Mod(neg, bigN))
		jacDoubleScalarMultVar(&r, &ls, &lneg, &jg)
		if p := r.toAffinePoint(); !p.Infinity {
			t.Fatalf("[s]G+[-s]G = %s", p.ToHexEncoded())
		}

		jacDoubleScalarMultVar(&r, &ls, nil, nil)
		checkPoint(t, "[s]G", r.toAffinePoint(), refMul(refG, s))

		jacScalarMultVar(&r, &jp, &ls)
		checkPoint(t, "[s]P var", r.toAffinePoint(), refMul(refP, s))
	}
}

func TestWNAFRecode(t *testing.T) {
	rng := rand.New(rand.NewSource(14))
	for _, k := range edgeScalars(rng, 100) {
		l := bigToLimbs(k)
		for _, w := range []uint{varWNAFWidth, baseWNAFWidth} {
			var digits [258]int16
			n := wnafRecode(&digits, &l, w)
			sum := new(big.Int)
			for i := n - 1; i >= 0; i-- {
				sum.Lsh(sum, 1)
				sum.Add(sum, big.NewInt(int64(digits[i])))
				if d := digits[i]; d != 0 && (d&1 == 0 || d >= 1<<(w-1) || d <= -(1<<(w-1))) {
					t.Fatalf("bad digit %d for w=%d", d, w)
				}
			}
			if sum.Cmp(k) != 0 {
				t.Fatalf("wNAF of %x (w=%d) sums to %x", k, w, sum)
			}
		}
	}
}

func TestBoothDigits(t *testing.T) {
	rng := rand.New(rand.NewSource(15))
	for _, k := range edgeScalars(rng, 100) {
		l := bigToLimbs(k)
		for _, tc := range []struct{ w, count uint }{{varWindow, varWindows}, {combWindow, combWindows}} {
			sum := new(big.Int)
			for i := int(tc.count) - 1; i >= 0; i-- {
				sum.Lsh(sum, tc.w)
				magnitude, negative := boothDigit(&l, uint(i)*tc.w, tc.w)
				if magnitude > 1<<(tc.w-1) {
					t.Fatalf("digit magnitude %d for w=%d", magnitude, tc.w)
				}
				d := big.NewInt(int64(magnitude))
				if negative != 0 {
					d.Neg(d)
				}
				sum.Add(sum, d)
			}
			if sum.Cmp(k) != 0 {
				t.Fatalf("Booth digits of %x (w=%d) sum to %x", k, tc.w, sum)
			}
		}
	}
}

func TestBaseTables(t *testing.T) {
	tables := baseTables()
	for i, row := range tables.comb {
		base := new(big.Int).Lsh(big.NewInt(1), uint(i*combWindow))
		for _, j := range []int{0, 1, 2, combTableSize - 1} {
			k := new(big.Int).Mul(base, big.NewInt(int64(j+1)))
			want := refMul(refG, k.Mod(k, bigN))
			if limbsToBig(feFromMont(&row[j].x)).Cmp(want.x) != 0 || limbsToBig(feFromMont(&row[j].y)).Cmp(want.y) != 0 {
				t.Fatalf("comb[%d][%d] wrong", i, j)
			}
		}
	}
	for j := range tables.wnaf {
		want := refMul(refG, big.NewInt(int64(2*j+1)))
		e := &tables.wnaf[j]
		if limbsToBig(feFromMont(&e.x)).Cmp(want.x) != 0 || limbsToBig(feFromMont(&e.y)).Cmp(want.y) != 0 {
			t.Fatalf("wnaf[%d] wrong", j)
		}
	}
}

func TestIsOnCurveDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(16))
	refOn := func(x, y *big.Int) bool {
		lhs := new(big.Int).Mul(y, y)
		lhs.Mod(lhs, bigP)
		rhs := new(big.Int).Exp(x, big.NewInt(3), bigP)
		rhs.Add(rhs, new(big.Int).Mul(refA, x))
		rhs.Add(rhs, limbsToBig(SM2_B.value.limbs)).Mod(rhs, bigP)
		return lhs.Cmp(rhs) == 0
	}
	values := reduced(diffValues(rng, 200), bigP)
	for _, x := range values {
		y := values[rng.Intn(len(values))]
		p := NewECPoint(FpElement{BigInt256{limbs: bigToLimbs(x)}}, FpElement{BigInt256{limbs: bigToLimbs(y)}})
		if p.IsOnCurve() != refOn(x, y) {
			t.Fatalf("IsOnCurve(%x, %x) = %v", x, y, p.IsOnCurve())
		}
	}
	for i := 0; i < 50; i++ {
		k := new(big.Int).Rand(rng, bigN)
		p := refMul(refG, k)
		if p.x == nil {
			continue
		}
		on := refToEC(p)
		if !on.IsOnCurve() {
			t.Fatalf("[%x]G reported off curve", k)
		}
		off := on
		off.Y = off.Y.Add(FpOne())
		if off.IsOnCurve() {
			t.Fatalf("perturbed [%x]G reported on curve", k)
		}
	}
}

// The projective comparison in verification must agree with the affine definition,
// including e >= n, x >= n and r - e == 0.
func TestVerifyCheckR(t *testing.T) {
	rng := rand.New(rand.NewSource(17))
	affine := func(p *jacPoint, e, r *BigInt256) bool {
		a := p.toAffinePoint()
		computed := e.ModAdd(&a.X.value, &SM2_N)
		return *r == computed
	}
	for i := 0; i < 300; i++ {
		k := new(big.Int).Add(new(big.Int).Rand(rng, new(big.Int).Sub(bigN, big.NewInt(1))), big.NewInt(1))
		kb := BigInt256{limbs: bigToLimbs(k)}
		jp := sm2BaseMult(&kb)
		// Scale z so the projective form is not trivial.
		var scale, scale2, scale3 fe
		feToMont(&scale, &[4]uint64{uint64(i) + 2, 0, 0, 0})
		feSqr(&scale2, &scale)
		feMul(&scale3, &scale2, &scale)
		feMul(&jp.x, &jp.x, &scale2)
		feMul(&jp.y, &jp.y, &scale3)
		feMul(&jp.z, &jp.z, &scale)

		x := jp.toAffinePoint().X.value
		es := []BigInt256{
			{limbs: bigToLimbs(new(big.Int).Rand(rng, bigN))},
			{limbs: bigToLimbs(new(big.Int).Sub(bigN, big.NewInt(1)))},
			SM2_N,
			{limbs: [4]uint64{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}},
			{limbs: [4]uint64{1}},
			verifyFastLimit,
			{limbs: bigToLimbs(new(big.Int).Sub(limbsToBig(verifyFastLimit.limbs), big.NewInt(1)))},
		}
		for _, e := range es {
			e := e
			good := e.ModAdd(&x, &SM2_N)
			others := []BigInt256{good, SM2_N, {limbs: [4]uint64{1}}, {limbs: bigToLimbs(new(big.Int).Rand(rng, bigN))}}
			for _, r := range others {
				r := r
				if r.IsZero() || r.Compare(&SM2_N) >= 0 {
					continue
				}
				if got, want := verifyCheckR(&jp, &e, &r), affine(&jp, &e, &r); got != want {
					t.Fatalf("verifyCheckR(e=%x, r=%x) = %v, want %v", e.limbs, r.limbs, got, want)
				}
			}
		}
	}
}
