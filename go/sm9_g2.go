package smx

// G2 of SM9: the order-N subgroup of the twist y^2 = x^3 + 5u over Fq2. The twist has a
// large cofactor, so every decoded point is checked for membership in the subgroup.

type sm9G2Jac struct{ x, y, z sm9Fp2 }

type sm9G2Aff struct{ x, y sm9Fp2 }

var (
	sm9P2 = sm9G2Aff{
		sm9Fp2{
			sm9Fp{0x260226A68CE2DA8F, 0x7EE5645EDBF6C06B, 0xF8F57C82B1495444, 0x61FCF018BC47C4D1},
			sm9Fp{0xDB6DB4822750A8A6, 0x84C6135A5121F134, 0x1874032F88791D41, 0x905112F2B85F3A37},
		},
		sm9Fp2{
			sm9Fp{0xC03F138F9171C24A, 0x92FBAB45A15A3CA7, 0x2445561E2FF77CDB, 0x108495E0C0F62ECE},
			sm9Fp{0xF7B82DAC4C89BFBB, 0x3706F3F6A49DC12F, 0x1E29DE93D3EEF769, 0x81E448C3C76A5D53},
		},
	}

	// sm9TwistB is the twist coefficient 5u.
	sm9TwistB = sm9Fp2{a1: sm9FpB}

	// sm9TwistPiX and sm9TwistPiY are u^(-(q-1)/3) and u^(-(q-1)/2), both in Fq: the
	// Frobenius map on the twist is (x, y) -> (conj(x)*sm9TwistPiX, conj(y)*sm9TwistPiY).
	sm9TwistPiX = sm9Fp{0x646A4B5A4E6783B9, 0xD5E4017F8D980F9D, 0x8D8BF6FD0CDFE790, 0x2D4AC18B775A8F7B}
	sm9TwistPiY = sm9Fp{0xABBAAC18A46A2054, 0x46EE57561222C759, 0x1DAE609FA0E23561, 0x1DF7113DAE0ADC3C}
)

func (p *sm9G2Aff) jac() sm9G2Jac { return sm9G2Jac{p.x, p.y, sm9Fp2One()} }

func (p *sm9G2Jac) isInfinity() bool { return sm9Fp2IsZeroMask(&p.z) != 0 }

// sm9G2Double sets r = 2p (dbl-2009-l for a = 0).
func sm9G2Double(r, p *sm9G2Jac) {
	var a, b, c, d, e, f, t, x3, y3, z3 sm9Fp2
	sm9Fp2Sqr(&a, &p.x)
	sm9Fp2Sqr(&b, &p.y)
	sm9Fp2Sqr(&c, &b)
	sm9Fp2Add(&d, &p.x, &b)
	sm9Fp2Sqr(&d, &d)
	sm9Fp2Sub(&d, &d, &a)
	sm9Fp2Sub(&d, &d, &c)
	sm9Fp2Double(&d, &d)
	sm9Fp2Double(&e, &a)
	sm9Fp2Add(&e, &e, &a)
	sm9Fp2Sqr(&f, &e)
	sm9Fp2Double(&t, &d)
	sm9Fp2Sub(&x3, &f, &t)
	sm9Fp2Sub(&t, &d, &x3)
	sm9Fp2Mul(&y3, &e, &t)
	sm9Fp2Double(&c, &c)
	sm9Fp2Double(&c, &c)
	sm9Fp2Double(&c, &c)
	sm9Fp2Sub(&y3, &y3, &c)
	sm9Fp2Mul(&z3, &p.y, &p.z)
	sm9Fp2Double(&z3, &z3)
	r.x, r.y, r.z = x3, y3, z3
}

// sm9G2AddFormula is sm9G1AddFormula over Fq2.
func sm9G2AddFormula(r, p, q *sm9G2Jac) (hZero, sZero uint64) {
	var z1z1, z2z2, u1, u2, s1, s2, h, hh, hhh, v, s, x3, y3, z3, t sm9Fp2
	sm9Fp2Sqr(&z1z1, &p.z)
	sm9Fp2Sqr(&z2z2, &q.z)
	sm9Fp2Mul(&u1, &p.x, &z2z2)
	sm9Fp2Mul(&u2, &q.x, &z1z1)
	sm9Fp2Mul(&s1, &p.y, &q.z)
	sm9Fp2Mul(&s1, &s1, &z2z2)
	sm9Fp2Mul(&s2, &q.y, &p.z)
	sm9Fp2Mul(&s2, &s2, &z1z1)
	sm9Fp2Sub(&h, &u2, &u1)
	sm9Fp2Sub(&s, &s2, &s1)
	hZero, sZero = sm9Fp2IsZeroMask(&h), sm9Fp2IsZeroMask(&s)
	sm9Fp2Sqr(&hh, &h)
	sm9Fp2Mul(&hhh, &hh, &h)
	sm9Fp2Mul(&v, &u1, &hh)
	sm9Fp2Sqr(&x3, &s)
	sm9Fp2Sub(&x3, &x3, &hhh)
	sm9Fp2Double(&t, &v)
	sm9Fp2Sub(&x3, &x3, &t)
	sm9Fp2Sub(&t, &v, &x3)
	sm9Fp2Mul(&y3, &s, &t)
	sm9Fp2Mul(&t, &s1, &hhh)
	sm9Fp2Sub(&y3, &y3, &t)
	sm9Fp2Mul(&z3, &p.z, &q.z)
	sm9Fp2Mul(&z3, &z3, &h)
	r.x, r.y, r.z = x3, y3, z3
	return hZero, sZero
}

func sm9G2Select(r, p *sm9G2Jac, mask uint64) {
	sm9Fp2Select(&r.x, &p.x, mask)
	sm9Fp2Select(&r.y, &p.y, mask)
	sm9Fp2Select(&r.z, &p.z, mask)
}

func sm9G2AddComplete(r, p, q *sm9G2Jac) {
	var sum, twice sm9G2Jac
	hZero, sZero := sm9G2AddFormula(&sum, p, q)
	sm9G2Double(&twice, q)
	sm9G2Select(&sum, &twice, hZero&sZero)
	sm9G2Select(&sum, q, sm9Fp2IsZeroMask(&p.z))
	sm9G2Select(&sum, p, sm9Fp2IsZeroMask(&q.z))
	*r = sum
}

func sm9G2AddConst(r, p, q *sm9G2Jac) {
	var sum sm9G2Jac
	sm9G2AddFormula(&sum, p, q)
	sm9G2Select(&sum, q, sm9Fp2IsZeroMask(&p.z))
	sm9G2Select(&sum, p, sm9Fp2IsZeroMask(&q.z))
	*r = sum
}

// sm9G2AddVar branches on its inputs: public data only.
func sm9G2AddVar(r, p, q *sm9G2Jac) {
	switch {
	case p.isInfinity():
		*r = *q
	case q.isInfinity():
		*r = *p
	default:
		var sum sm9G2Jac
		hZero, sZero := sm9G2AddFormula(&sum, p, q)
		if hZero != 0 && sZero != 0 {
			sm9G2Double(r, q)
			return
		}
		*r = sum
	}
}

// sm9G2ScalarMult sets r = [k]p for k below N and p in G2, constant time in k; see
// sm9G1ScalarMult.
func sm9G2ScalarMult(r, p *sm9G2Jac, k *[4]uint64) {
	var table [varTableSize]sm9G2Jac
	table[0] = *p
	for i := 1; i < varTableSize; i++ {
		if i%2 == 1 {
			sm9G2Double(&table[i], &table[i/2])
		} else {
			sm9G2AddConst(&table[i], &table[i-1], p)
		}
	}
	acc := sm9G2Jac{x: sm9Fp2One(), y: sm9Fp2One()}
	var entry sm9G2Jac
	for w := varWindows - 1; w >= 0; w-- {
		if w != varWindows-1 {
			for i := 0; i < varWindow; i++ {
				sm9G2Double(&acc, &acc)
			}
		}
		magnitude, negative := boothDigit(k, uint(w)*varWindow, varWindow)
		entry = sm9G2Jac{}
		for i := range table {
			sm9G2Select(&entry, &table[i], ctEqMask(uint64(i+1), magnitude))
		}
		var negY sm9Fp2
		sm9Fp2Neg(&negY, &entry.y)
		sm9Fp2Select(&entry.y, &negY, negative)
		if w == 0 {
			sm9G2AddComplete(&acc, &acc, &entry)
		} else {
			sm9G2AddConst(&acc, &acc, &entry)
		}
	}
	*r = acc
}

// sm9G2ScalarMultVar sets r = [k]p for any 256-bit public k with width-5 wNAF. It
// branches on k and on the points: public data only.
func sm9G2ScalarMultVar(r, p *sm9G2Jac, k *[4]uint64) {
	var table [1 << (varWNAFWidth - 2)]sm9G2Jac
	var twice sm9G2Jac
	sm9G2Double(&twice, p)
	table[0] = *p
	for i := 1; i < len(table); i++ {
		sm9G2AddVar(&table[i], &table[i-1], &twice)
	}
	var digits [258]int16
	top := wnafRecode(&digits, k, varWNAFWidth)
	acc := sm9G2Jac{x: sm9Fp2One(), y: sm9Fp2One()}
	for i := top - 1; i >= 0; i-- {
		sm9G2Double(&acc, &acc)
		if d := digits[i]; d > 0 {
			sm9G2AddVar(&acc, &acc, &table[d>>1])
		} else if d < 0 {
			q := table[(-d)>>1]
			sm9Fp2Neg(&q.y, &q.y)
			sm9G2AddVar(&acc, &acc, &q)
		}
	}
	*r = acc
}

func (p *sm9G2Jac) toAffine() (sm9G2Aff, bool) {
	if p.isInfinity() {
		return sm9G2Aff{}, false
	}
	var zi, zi2, zi3 sm9Fp2
	var out sm9G2Aff
	sm9Fp2Inv(&zi, &p.z)
	sm9Fp2Sqr(&zi2, &zi)
	sm9Fp2Mul(&zi3, &zi2, &zi)
	sm9Fp2Mul(&out.x, &p.x, &zi2)
	sm9Fp2Mul(&out.y, &p.y, &zi3)
	return out, true
}

// onCurve reports whether y^2 == x^3 + 5u.
func (p *sm9G2Aff) onCurve() bool {
	var l, r sm9Fp2
	sm9Fp2Sqr(&l, &p.y)
	sm9Fp2Sqr(&r, &p.x)
	sm9Fp2Mul(&r, &r, &p.x)
	sm9Fp2Add(&r, &r, &sm9TwistB)
	return sm9Fp2EqualMask(&l, &r) != 0
}

// inSubgroup reports whether [N]p is the identity. The schedule depends only on the
// public N; the only data-dependent branches are the identity and doubling cases of the
// additions, which a point of order N meets only at the very end.
func (p *sm9G2Aff) inSubgroup() bool {
	j := p.jac()
	var r sm9G2Jac
	sm9G2ScalarMultVar(&r, &j, &sm9N)
	return r.isInfinity()
}

// frob returns pi(p) = (conj(x) * PiX, conj(y) * PiY).
func (p *sm9G2Aff) frob() sm9G2Aff {
	var out sm9G2Aff
	sm9Fp2Conj(&out.x, &p.x)
	sm9Fp2MulFp(&out.x, &out.x, &sm9TwistPiX)
	sm9Fp2Conj(&out.y, &p.y)
	sm9Fp2MulFp(&out.y, &out.y, &sm9TwistPiY)
	return out
}

// sm9G2FromBytes decodes 04 || x1 || x0 || y1 || y0 and reports whether it is a point of
// G2: coordinates below q, on the twist, and in the order-N subgroup.
func sm9G2FromBytes(b []byte) (sm9G2Aff, bool) {
	var p sm9G2Aff
	if len(b) != 129 || b[0] != 4 {
		return p, false
	}
	ok := sm9FpSetBytes(&p.x.a1, b[1:33])
	ok = sm9FpSetBytes(&p.x.a0, b[33:65]) && ok
	ok = sm9FpSetBytes(&p.y.a1, b[65:97]) && ok
	ok = sm9FpSetBytes(&p.y.a0, b[97:129]) && ok
	if !ok || !p.onCurve() || !p.inSubgroup() {
		return sm9G2Aff{}, false
	}
	return p, true
}

// bytes returns 04 || x1 || x0 || y1 || y0.
func (p *sm9G2Aff) bytes() [129]byte {
	var out [129]byte
	out[0] = 4
	sm9FpPutBytes(out[1:], &p.x.a1)
	sm9FpPutBytes(out[33:], &p.x.a0)
	sm9FpPutBytes(out[65:], &p.y.a1)
	sm9FpPutBytes(out[97:], &p.y.a0)
	return out
}

// sm9G2Mul returns [k]p in affine form, constant time in k, and false for the identity.
func sm9G2Mul(p *sm9G2Aff, k *[4]uint64) (sm9G2Aff, bool) {
	j := p.jac()
	var r sm9G2Jac
	sm9G2ScalarMult(&r, &j, k)
	return r.toAffine()
}
