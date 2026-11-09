package smx

// G1 of SM9: the curve y^2 = x^3 + 5 over Fq, of prime order N.

// sm9G1Jac is a point in Jacobian coordinates (x/z^2, y/z^3); z == 0 is the identity.
type sm9G1Jac struct{ x, y, z sm9Fp }

// sm9G1Aff is a finite point in affine coordinates.
type sm9G1Aff struct{ x, y sm9Fp }

var sm9P1 = sm9G1Aff{
	sm9Fp{0x22E935E29860501B, 0xA946FD5E0073282C, 0xEFD0CEC817A649BE, 0x5129787C869140B5},
	sm9Fp{0xEE779649EB87F7C7, 0x15563CBDEC30A576, 0x326353912824EFBF, 0x7215717763C39828},
}

func (p *sm9G1Aff) jac() sm9G1Jac { return sm9G1Jac{p.x, p.y, sm9FpOne} }

func (p *sm9G1Jac) isInfinity() bool { return sm9FpIsZeroMask(&p.z) != 0 }

// sm9G1Double sets r = 2p (dbl-2009-l for a = 0). The identity gives z == 0.
func sm9G1Double(r, p *sm9G1Jac) {
	var a, b, c, d, e, f, t, x3, y3, z3 sm9Fp
	sm9FpSqr(&a, &p.x)
	sm9FpSqr(&b, &p.y)
	sm9FpSqr(&c, &b)
	sm9FpAdd(&d, &p.x, &b)
	sm9FpSqr(&d, &d)
	sm9FpSub(&d, &d, &a)
	sm9FpSub(&d, &d, &c)
	sm9FpDouble(&d, &d)
	sm9FpDouble(&e, &a)
	sm9FpAdd(&e, &e, &a)
	sm9FpSqr(&f, &e)
	sm9FpDouble(&t, &d)
	sm9FpSub(&x3, &f, &t)
	sm9FpSub(&t, &d, &x3)
	sm9FpMul(&y3, &e, &t)
	sm9FpDouble(&c, &c)
	sm9FpDouble(&c, &c)
	sm9FpDouble(&c, &c)
	sm9FpSub(&y3, &y3, &c)
	sm9FpMul(&z3, &p.y, &p.z)
	sm9FpDouble(&z3, &z3)
	r.x, r.y, r.z = x3, y3, z3
}

// sm9G1AddFormula sets r = p + q (add-1998-cmo-2) for finite p != q and returns the masks
// of h == 0 and s == 0. For p == -q it gives z == 0.
func sm9G1AddFormula(r, p, q *sm9G1Jac) (hZero, sZero uint64) {
	var z1z1, z2z2, u1, u2, s1, s2, h, hh, hhh, v, s, x3, y3, z3, t sm9Fp
	sm9FpSqr(&z1z1, &p.z)
	sm9FpSqr(&z2z2, &q.z)
	sm9FpMul(&u1, &p.x, &z2z2)
	sm9FpMul(&u2, &q.x, &z1z1)
	sm9FpMul(&s1, &p.y, &q.z)
	sm9FpMul(&s1, &s1, &z2z2)
	sm9FpMul(&s2, &q.y, &p.z)
	sm9FpMul(&s2, &s2, &z1z1)
	sm9FpSub(&h, &u2, &u1)
	sm9FpSub(&s, &s2, &s1)
	hZero, sZero = sm9FpIsZeroMask(&h), sm9FpIsZeroMask(&s)
	sm9FpSqr(&hh, &h)
	sm9FpMul(&hhh, &hh, &h)
	sm9FpMul(&v, &u1, &hh)
	sm9FpSqr(&x3, &s)
	sm9FpSub(&x3, &x3, &hhh)
	sm9FpDouble(&t, &v)
	sm9FpSub(&x3, &x3, &t)
	sm9FpSub(&t, &v, &x3)
	sm9FpMul(&y3, &s, &t)
	sm9FpMul(&t, &s1, &hhh)
	sm9FpSub(&y3, &y3, &t)
	sm9FpMul(&z3, &p.z, &q.z)
	sm9FpMul(&z3, &z3, &h)
	r.x, r.y, r.z = x3, y3, z3
	return hZero, sZero
}

func sm9G1Select(r, p *sm9G1Jac, mask uint64) {
	sm9FpSelect(&r.x, &p.x, mask)
	sm9FpSelect(&r.y, &p.y, mask)
	sm9FpSelect(&r.z, &p.z, mask)
}

// sm9G1AddComplete sets r = p + q for all inputs without branching on coordinates.
func sm9G1AddComplete(r, p, q *sm9G1Jac) {
	var sum, twice sm9G1Jac
	hZero, sZero := sm9G1AddFormula(&sum, p, q)
	sm9G1Double(&twice, q)
	sm9G1Select(&sum, &twice, hZero&sZero)
	sm9G1Select(&sum, q, sm9FpIsZeroMask(&p.z))
	sm9G1Select(&sum, p, sm9FpIsZeroMask(&q.z))
	*r = sum
}

// sm9G1AddConst is sm9G1AddComplete without the doubling case p == q.
func sm9G1AddConst(r, p, q *sm9G1Jac) {
	var sum sm9G1Jac
	sm9G1AddFormula(&sum, p, q)
	sm9G1Select(&sum, q, sm9FpIsZeroMask(&p.z))
	sm9G1Select(&sum, p, sm9FpIsZeroMask(&q.z))
	*r = sum
}

// sm9G1AddVar sets r = p + q for all inputs, branching on them: public data only.
func sm9G1AddVar(r, p, q *sm9G1Jac) {
	switch {
	case p.isInfinity():
		*r = *q
	case q.isInfinity():
		*r = *p
	default:
		var sum sm9G1Jac
		hZero, sZero := sm9G1AddFormula(&sum, p, q)
		if hZero != 0 && sZero != 0 {
			sm9G1Double(r, q)
			return
		}
		*r = sum
	}
}

// sm9G1ScalarMult sets r = [k]p for k below N and p of order N (or the identity), in
// constant time with respect to k: a fixed 5-bit signed window, a masked scan of the
// whole table for every digit, and no branch on secret data. As in jacScalarMult, only
// the last window can meet the doubling case, so it alone uses the complete addition.
func sm9G1ScalarMult(r, p *sm9G1Jac, k *[4]uint64) {
	var table [varTableSize]sm9G1Jac
	table[0] = *p
	for i := 1; i < varTableSize; i++ {
		if i%2 == 1 {
			sm9G1Double(&table[i], &table[i/2])
		} else {
			sm9G1AddConst(&table[i], &table[i-1], p)
		}
	}
	acc := sm9G1Jac{x: sm9FpOne, y: sm9FpOne}
	var entry sm9G1Jac
	for w := varWindows - 1; w >= 0; w-- {
		if w != varWindows-1 {
			for i := 0; i < varWindow; i++ {
				sm9G1Double(&acc, &acc)
			}
		}
		magnitude, negative := boothDigit(k, uint(w)*varWindow, varWindow)
		entry = sm9G1Jac{}
		for i := range table {
			mask := ctEqMask(uint64(i+1), magnitude)
			sm9G1Select(&entry, &table[i], mask)
		}
		var negY sm9Fp
		sm9FpNeg(&negY, &entry.y)
		sm9FpSelect(&entry.y, &negY, negative)
		if w == 0 {
			sm9G1AddComplete(&acc, &acc, &entry)
		} else {
			sm9G1AddConst(&acc, &acc, &entry)
		}
	}
	*r = acc
}

// sm9G1ScalarMultVar sets r = [k]p for any 256-bit public k with width-5 wNAF. It
// branches on k and on the points: public data only.
func sm9G1ScalarMultVar(r, p *sm9G1Jac, k *[4]uint64) {
	var table [1 << (varWNAFWidth - 2)]sm9G1Jac
	var twice sm9G1Jac
	sm9G1Double(&twice, p)
	table[0] = *p
	for i := 1; i < len(table); i++ {
		sm9G1AddVar(&table[i], &table[i-1], &twice)
	}
	var digits [258]int16
	top := wnafRecode(&digits, k, varWNAFWidth)
	acc := sm9G1Jac{x: sm9FpOne, y: sm9FpOne}
	for i := top - 1; i >= 0; i-- {
		sm9G1Double(&acc, &acc)
		if d := digits[i]; d > 0 {
			sm9G1AddVar(&acc, &acc, &table[d>>1])
		} else if d < 0 {
			q := table[(-d)>>1]
			sm9FpNeg(&q.y, &q.y)
			sm9G1AddVar(&acc, &acc, &q)
		}
	}
	*r = acc
}

func (p *sm9G1Jac) toAffine() (sm9G1Aff, bool) {
	if p.isInfinity() {
		return sm9G1Aff{}, false
	}
	var zi, zi2, out sm9G1Aff
	sm9FpInv(&zi.x, &p.z)
	sm9FpSqr(&zi2.x, &zi.x)
	sm9FpMul(&zi2.y, &zi2.x, &zi.x)
	sm9FpMul(&out.x, &p.x, &zi2.x)
	sm9FpMul(&out.y, &p.y, &zi2.y)
	return out, true
}

// onCurve reports whether y^2 == x^3 + 5.
func (p *sm9G1Aff) onCurve() bool {
	var l, r sm9Fp
	sm9FpSqr(&l, &p.y)
	sm9FpSqr(&r, &p.x)
	sm9FpMul(&r, &r, &p.x)
	sm9FpAdd(&r, &r, &sm9FpB)
	return sm9FpEqualMask(&l, &r) != 0
}

// sm9G1FromBytes decodes 04 || x || y and reports whether it is a point of G1 (on the
// curve, coordinates below q; the identity has no such encoding). G1 has cofactor 1.
func sm9G1FromBytes(b []byte) (sm9G1Aff, bool) {
	var p sm9G1Aff
	if len(b) != 65 || b[0] != 4 {
		return p, false
	}
	okX := sm9FpSetBytes(&p.x, b[1:33])
	okY := sm9FpSetBytes(&p.y, b[33:65])
	if !okX || !okY || !p.onCurve() {
		return sm9G1Aff{}, false
	}
	return p, true
}

// bytes returns 04 || x || y.
func (p *sm9G1Aff) bytes() [65]byte {
	var out [65]byte
	out[0] = 4
	sm9FpPutBytes(out[1:], &p.x)
	sm9FpPutBytes(out[33:], &p.y)
	return out
}

// sm9G1Mul returns [k]p in affine form, constant time in k, and false for the identity.
func sm9G1Mul(p *sm9G1Aff, k *[4]uint64) (sm9G1Aff, bool) {
	j := p.jac()
	var r sm9G1Jac
	sm9G1ScalarMult(&r, &j, k)
	return r.toAffine()
}
