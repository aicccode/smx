package smx

import (
	"encoding/hex"
	"math/big"
	"math/rand"
	"testing"
)

// Differential tests of the limb arithmetic against math/big.

var (
	bigP = new(big.Int).SetBytes(hexMust("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"))
	bigN = new(big.Int).SetBytes(hexMust("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"))
	bigR = new(big.Int).Lsh(big.NewInt(1), 256)
)

func hexMust(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func limbsToBig(l [4]uint64) *big.Int {
	x := new(big.Int)
	for i := 3; i >= 0; i-- {
		x.Lsh(x, 64)
		x.Or(x, new(big.Int).SetUint64(l[i]))
	}
	return x
}

func bigToLimbs(x *big.Int) [4]uint64 {
	var buf [32]byte
	x.FillBytes(buf[:])
	return BigInt256FromBEBytes(buf[:]).limbs
}

// edgeValues lists the 256-bit values most likely to expose carry bugs.
func edgeValues() []*big.Int {
	one := big.NewInt(1)
	max := new(big.Int).Sub(bigR, one)
	values := []*big.Int{
		big.NewInt(0), one, big.NewInt(2), big.NewInt(3),
		new(big.Int).Sub(bigP, one), new(big.Int).Sub(bigP, big.NewInt(2)), bigP, new(big.Int).Add(bigP, one),
		new(big.Int).Sub(bigN, one), new(big.Int).Sub(bigN, big.NewInt(2)), bigN, new(big.Int).Add(bigN, one),
		max, new(big.Int).Sub(max, one),
		new(big.Int).Lsh(one, 255), new(big.Int).Lsh(one, 224), new(big.Int).Lsh(one, 192),
		new(big.Int).Lsh(one, 128), new(big.Int).Lsh(one, 96), new(big.Int).Lsh(one, 64), new(big.Int).Lsh(one, 32),
		new(big.Int).Sub(new(big.Int).Lsh(one, 64), one),
		new(big.Int).Sub(new(big.Int).Lsh(one, 128), one),
		new(big.Int).Sub(new(big.Int).Lsh(one, 192), one),
	}
	// Maximal carries: every limb all ones or all zero.
	for mask := 0; mask < 16; mask++ {
		var l [4]uint64
		for i := range l {
			if mask>>i&1 == 1 {
				l[i] = ^uint64(0)
			}
		}
		values = append(values, limbsToBig(l))
	}
	return values
}

// diffValues returns the edge values plus random values with varied limb patterns.
func diffValues(rng *rand.Rand, random int) []*big.Int {
	values := edgeValues()
	for i := 0; i < random; i++ {
		var l [4]uint64
		for j := range l {
			switch rng.Intn(5) {
			case 0:
				l[j] = ^uint64(0)
			case 1:
				l[j] = 0
			case 2:
				l[j] = uint64(rng.Uint32())
			default:
				l[j] = rng.Uint64()
			}
		}
		values = append(values, limbsToBig(l))
	}
	return values
}

func reduced(values []*big.Int, m *big.Int) []*big.Int {
	out := make([]*big.Int, len(values))
	for i, v := range values {
		out[i] = new(big.Int).Mod(v, m)
	}
	return out
}

func toMontBig(x *big.Int) fe {
	v := new(big.Int).Mul(x, bigR)
	return fe(bigToLimbs(v.Mod(v, bigP)))
}

func fromMontBig(x *fe) *big.Int {
	v := new(big.Int).Mul(limbsToBig(*x), new(big.Int).ModInverse(bigR, bigP))
	return v.Mod(v, bigP)
}

func checkLimbs(t *testing.T, op string, got [4]uint64, want *big.Int, args ...*big.Int) {
	t.Helper()
	if limbsToBig(got).Cmp(want) != 0 {
		t.Fatalf("%s%x = %x, want %x", op, args, limbsToBig(got), want)
	}
}

func TestFieldConstants(t *testing.T) {
	checkLimbs(t, "R mod p", feOne, new(big.Int).Mod(bigR, bigP))
	checkLimbs(t, "R^2 mod p", feRR, new(big.Int).Exp(bigR, big.NewInt(2), bigP))
	checkLimbs(t, "R^2 mod n", scalarRR, new(big.Int).Exp(bigR, big.NewInt(2), bigN))
	checkLimbs(t, "p", SM2_P.limbs, bigP)
	checkLimbs(t, "n", SM2_N.limbs, bigN)
	checkLimbs(t, "n", [4]uint64{n0, n1, n2, n3}, bigN)
	b := limbsToBig(SM2_B.value.limbs)
	checkLimbs(t, "b*R", feB, new(big.Int).Mod(new(big.Int).Mul(b, bigR), bigP))

	inv := new(big.Int).ModInverse(bigN, new(big.Int).Lsh(big.NewInt(1), 64))
	inv.Neg(inv).Mod(inv, new(big.Int).Lsh(big.NewInt(1), 64))
	if inv.Uint64() != nInv {
		t.Fatalf("nInv = %x, want %x", uint64(nInv), inv)
	}
}

func TestFeDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	values := reduced(diffValues(rng, 300), bigP)
	mod := func(x *big.Int) *big.Int { return x.Mod(x, bigP) }

	for _, a := range values {
		ma := toMontBig(a)
		var z fe

		feToMont(&z, bigLimbs(a))
		checkLimbs(t, "feToMont", z, limbsToBig(ma), a)
		checkLimbs(t, "feFromMont", feFromMont(&ma), a, a)

		feSqr(&z, &ma)
		checkLimbs(t, "feSqr", feFromMont(&z), mod(new(big.Int).Mul(a, a)), a)

		feDouble(&z, &ma)
		checkLimbs(t, "feDouble", feFromMont(&z), mod(new(big.Int).Lsh(a, 1)), a)

		feNeg(&z, &ma)
		checkLimbs(t, "feNeg", feFromMont(&z), mod(new(big.Int).Neg(a)), a)

		feInvert(&z, &ma)
		want := new(big.Int)
		if a.Sign() != 0 {
			want.ModInverse(a, bigP)
		}
		checkLimbs(t, "feInvert", feFromMont(&z), want, a)

		wantZero := uint64(0)
		if a.Sign() == 0 {
			wantZero = ^uint64(0)
		}
		if got := feIsZeroMask(&ma); got != wantZero {
			t.Fatalf("feIsZeroMask(%x) = %x", a, got)
		}

		for i := 0; i < 8; i++ {
			b := values[rng.Intn(len(values))]
			mb := toMontBig(b)

			feMul(&z, &ma, &mb)
			checkLimbs(t, "feMul", feFromMont(&z), mod(new(big.Int).Mul(a, b)), a, b)

			feAdd(&z, &ma, &mb)
			checkLimbs(t, "feAdd", feFromMont(&z), mod(new(big.Int).Add(a, b)), a, b)

			feSub(&z, &ma, &mb)
			checkLimbs(t, "feSub", feFromMont(&z), mod(new(big.Int).Sub(a, b)), a, b)

			// Aliased output.
			y := ma
			feMul(&y, &y, &mb)
			checkLimbs(t, "feMul alias", feFromMont(&y), mod(new(big.Int).Mul(a, b)), a, b)
		}
	}
}

// feMul accepts one unreduced input, up to 2^256 - 1.
func TestFeMulUnreduced(t *testing.T) {
	rinv := new(big.Int).ModInverse(bigR, bigP)
	rng := rand.New(rand.NewSource(2))
	values := diffValues(rng, 300)
	for _, a := range values {
		x := fe(bigToLimbs(a))
		for i := 0; i < 8; i++ {
			b := new(big.Int).Mod(values[rng.Intn(len(values))], bigP)
			y := fe(bigToLimbs(b))
			var z fe
			feMul(&z, &x, &y)
			want := new(big.Int).Mul(a, b)
			want.Mul(want, rinv).Mod(want, bigP)
			checkLimbs(t, "feMul", z, want, a, b)
		}
		checkLimbs(t, "feReduce", feReduce(bigLimbs(a)), new(big.Int).Mod(a, bigP), a)
	}
}

func bigLimbs(x *big.Int) *[4]uint64 {
	l := bigToLimbs(x)
	return &l
}

func TestMul512Differential(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	values := diffValues(rng, 300)
	for _, a := range values {
		la := bigToLimbs(a)
		for i := 0; i < 8; i++ {
			b := values[rng.Intn(len(values))]
			lb := bigToLimbs(b)
			t0, t1, t2, t3, t4, t5, t6, t7 := mul512(&la, &lb)
			got := append(limbsToBytes([4]uint64{t4, t5, t6, t7}), limbsToBytes([4]uint64{t0, t1, t2, t3})...)
			if new(big.Int).SetBytes(got).Cmp(new(big.Int).Mul(a, b)) != 0 {
				t.Fatalf("mul512(%x, %x) wrong", a, b)
			}
		}
		t0, t1, t2, t3, t4, t5, t6, t7 := sqr512(&la)
		got := append(limbsToBytes([4]uint64{t4, t5, t6, t7}), limbsToBytes([4]uint64{t0, t1, t2, t3})...)
		if new(big.Int).SetBytes(got).Cmp(new(big.Int).Mul(a, a)) != 0 {
			t.Fatalf("sqr512(%x) wrong", a)
		}
	}
}

func limbsToBytes(l [4]uint64) []byte {
	b := BigInt256{limbs: l}.ToBEBytes()
	return b[:]
}

func TestScalarDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	values := diffValues(rng, 300)
	mod := func(x *big.Int) *big.Int { return x.Mod(x, bigN) }
	for _, a := range values {
		la := bigToLimbs(a)
		checkLimbs(t, "scalarReduce", scalarReduce(&la), mod(new(big.Int).Set(a)), a)

		var z [4]uint64
		scalarInvert(&z, &la)
		want := new(big.Int)
		if r := mod(new(big.Int).Set(a)); r.Sign() != 0 {
			want.ModInverse(r, bigN)
		}
		checkLimbs(t, "scalarInvert", z, want, a)

		inRange := a.Sign() > 0 && a.Cmp(bigN) < 0
		if scalarInRange(&la) != inRange {
			t.Fatalf("scalarInRange(%x) = %v", a, !inRange)
		}

		for i := 0; i < 8; i++ {
			b := values[rng.Intn(len(values))]
			lb := bigToLimbs(b)
			scalarMul(&z, &la, &lb)
			checkLimbs(t, "scalarMul", z, mod(new(big.Int).Mul(a, b)), a, b)
			if limbsEqual(&la, &lb) != (a.Cmp(b) == 0) {
				t.Fatalf("limbsEqual(%x, %x)", a, b)
			}
		}
		if !limbsEqual(&la, &la) {
			t.Fatalf("limbsEqual(%x, itself)", a)
		}
	}
}

// BigInt256's generic operations must match math/big on every modulus shape, including
// even moduli, tiny moduli and the two special primes.
func TestBigIntModDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	values := diffValues(rng, 200)
	moduli := append(diffValues(rng, 200),
		big.NewInt(7), big.NewInt(2), big.NewInt(1), big.NewInt(0x10001),
		new(big.Int).Lsh(big.NewInt(1), 64), new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 128), new(big.Int).Lsh(big.NewInt(3), 190))

	for _, mb := range moduli {
		if mb.Sign() == 0 {
			continue
		}
		m := BigInt256{limbs: bigToLimbs(mb)}
		for i := 0; i < 20; i++ {
			a := values[rng.Intn(len(values))]
			b := values[rng.Intn(len(values))]
			x, y := BigInt256{limbs: bigToLimbs(a)}, BigInt256{limbs: bigToLimbs(b)}

			want := new(big.Int).Mul(a, b)
			want.Mod(want, mb)
			checkLimbs(t, "ModMul", x.ModMul(&y, &m).limbs, want, a, b, mb)

			want = new(big.Int).Mul(a, a)
			want.Mod(want, mb)
			checkLimbs(t, "ModSquare", x.ModSquare(&m).limbs, want, a, mb)
		}
		// Exponentiation, with exponents of 0..256 bits.
		a := values[rng.Intn(len(values))]
		x := BigInt256{limbs: bigToLimbs(a)}
		for _, eb := range []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(16), big.NewInt(17), big.NewInt(0x10001),
			values[rng.Intn(len(values))]} {
			if eb.Sign() == 0 {
				continue
			}
			e := BigInt256{limbs: bigToLimbs(eb)}
			want := new(big.Int).Exp(a, eb, mb)
			checkLimbs(t, "ModPow", x.ModPow(&e, &m).limbs, want, a, eb, mb)
		}
		var zero BigInt256
		wantOne := new(big.Int).Mod(big.NewInt(1), mb) // 0 when m is 1
		checkLimbs(t, "ModPow(a, 0, m)", x.ModPow(&zero, &m).limbs, wantOne, a, mb)
	}

	// A zero or nil modulus gives zero rather than a crash.
	var zero BigInt256
	for _, m := range []*BigInt256{&zero, nil} {
		if !bigOne.ModMul(&bigOne, m).IsZero() || !bigOne.ModPow(&bigOne, m).IsZero() ||
			!bigOne.ModInverse(m).IsZero() || !bigOne.ModSquare(m).IsZero() {
			t.Fatal("zero modulus should give zero")
		}
	}
}

// ModAdd and ModSub keep their exact single-correction semantics even on unreduced
// inputs, because SM2 relies on them. This reference is the earlier implementation.
func TestModAddSubSemantics(t *testing.T) {
	refAdd := func(a, b, m BigInt256) BigInt256 {
		sum, carry := a.Add(&b)
		if carry != 0 || sum.Compare(&m) >= 0 {
			r, _ := sum.Sub(&m)
			return r
		}
		return sum
	}
	refSub := func(a, b, m BigInt256) BigInt256 {
		diff, borrow := a.Sub(&b)
		if borrow != 0 {
			r, _ := diff.Add(&m)
			return r
		}
		return diff
	}
	rng := rand.New(rand.NewSource(6))
	values := diffValues(rng, 100)
	for _, ab := range values {
		for i := 0; i < 50; i++ {
			a := BigInt256{limbs: bigToLimbs(ab)}
			b := BigInt256{limbs: bigToLimbs(values[rng.Intn(len(values))])}
			m := BigInt256{limbs: bigToLimbs(values[rng.Intn(len(values))])}
			if got, want := a.ModAdd(&b, &m), refAdd(a, b, m); got != want {
				t.Fatalf("ModAdd(%x, %x, %x) = %x, want %x", a.limbs, b.limbs, m.limbs, got.limbs, want.limbs)
			}
			if got, want := a.ModSub(&b, &m), refSub(a, b, m); got != want {
				t.Fatalf("ModSub(%x, %x, %x) = %x, want %x", a.limbs, b.limbs, m.limbs, got.limbs, want.limbs)
			}
		}
	}
}

func TestBigIntHelpersDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	one := big.NewInt(1)
	mask := new(big.Int).Sub(bigR, one)
	for _, a := range diffValues(rng, 200) {
		x := BigInt256{limbs: bigToLimbs(a)}
		other := diffValues(rng, 1)
		for _, b := range append(other, a) {
			y := BigInt256{limbs: bigToLimbs(b)}
			if got := x.Compare(&y); got != a.Cmp(b) {
				t.Fatalf("Compare(%x, %x) = %d", a, b, got)
			}
		}
		checkLimbs(t, "ShiftRight1", x.ShiftRight1().limbs, new(big.Int).Rsh(a, 1), a)
		checkLimbs(t, "ShiftLeft1", x.ShiftLeft1().limbs, new(big.Int).And(new(big.Int).Lsh(a, 1), mask), a)
		if x.BitLength() != a.BitLen() {
			t.Fatalf("BitLength(%x) = %d", a, x.BitLength())
		}
		if x.IsZero() != (a.Sign() == 0) || x.IsOne() != (a.Cmp(one) == 0) {
			t.Fatalf("IsZero/IsOne(%x)", a)
		}
		for i := 0; i < 256; i += 17 {
			if x.GetBit(i) != (a.Bit(i) == 1) {
				t.Fatalf("GetBit(%x, %d)", a, i)
			}
		}
		if x.GetBit(256) || x.GetBit(-1) || x.GetBit(-64) || x.GetBit(-1<<30) {
			t.Fatal("GetBit out of range should be false")
		}
		be := x.ToBEBytes()
		if BigInt256FromBEBytes(be[:]) != x {
			t.Fatalf("byte round trip %x", a)
		}
		product := x.Mul(&x)
		wide := append(limbsToBytes([4]uint64{product[4], product[5], product[6], product[7]}),
			limbsToBytes([4]uint64{product[0], product[1], product[2], product[3]})...)
		if new(big.Int).SetBytes(wide).Cmp(new(big.Int).Mul(a, a)) != 0 {
			t.Fatalf("Mul(%x)", a)
		}
	}
}

func TestFpElementDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(8))
	values := diffValues(rng, 200)
	mod := func(x *big.Int) *big.Int { return x.Mod(x, bigP) }
	for _, av := range values {
		a := new(big.Int).Mod(av, bigP)
		x := NewFpElement(BigInt256{limbs: bigToLimbs(av)})
		checkLimbs(t, "NewFpElement", x.value.limbs, a, av)

		checkLimbs(t, "Square", x.Square().value.limbs, mod(new(big.Int).Mul(a, a)), a)
		checkLimbs(t, "Double", x.Double().value.limbs, mod(new(big.Int).Lsh(a, 1)), a)
		checkLimbs(t, "Triple", x.Triple().value.limbs, mod(new(big.Int).Mul(a, big.NewInt(3))), a)
		checkLimbs(t, "Negate", x.Negate().value.limbs, mod(new(big.Int).Neg(a)), a)
		if a.Sign() != 0 {
			checkLimbs(t, "Invert", x.Invert().value.limbs, new(big.Int).ModInverse(a, bigP), a)
		}
		for i := 0; i < 5; i++ {
			b := new(big.Int).Mod(values[rng.Intn(len(values))], bigP)
			y := NewFpElement(BigInt256{limbs: bigToLimbs(b)})
			checkLimbs(t, "Add", x.Add(y).value.limbs, mod(new(big.Int).Add(a, b)), a, b)
			checkLimbs(t, "Sub", x.Sub(y).value.limbs, mod(new(big.Int).Sub(a, b)), a, b)
			checkLimbs(t, "Mul", x.Mul(y).value.limbs, mod(new(big.Int).Mul(a, b)), a, b)
			if b.Sign() != 0 {
				want := new(big.Int).Mul(a, new(big.Int).ModInverse(b, bigP))
				checkLimbs(t, "Div", x.Div(y).value.limbs, mod(want), a, b)
			}
		}
	}
	if !FpZero().Invert().IsZero() || !FpOne().Div(FpZero()).IsZero() {
		t.Fatal("inverting zero should give zero")
	}
}
