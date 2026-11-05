package smx

import "testing"

// Benchmarks of internal primitives, for profiling the layers below the public API.

func benchFeOperands() (fe, fe) {
	return fe{0x123456789ABCDEF0, 0xFEDCBA9876543210, 0x0F1E2D3C4B5A6978, 0x8796A5B4C3D2E1F0},
		fe{0x1111111122222222, 0x3333333344444444, 0x5555555566666666, 0x7777777788888888}
}

func benchPoint() jacPoint {
	d := BigInt256FromHex(benchPrivateKey)
	p := SM2GetPublicKey(&d)
	jp := jacFromAffinePoint(&p)
	jacDouble(&jp, &jp)
	return jp
}

func BenchmarkFeMul(b *testing.B) {
	x, y := benchFeOperands()
	for i := 0; i < b.N; i++ {
		feMul(&x, &x, &y)
	}
}

func BenchmarkFeSqr(b *testing.B) {
	x, _ := benchFeOperands()
	for i := 0; i < b.N; i++ {
		feSqr(&x, &x)
	}
}

func BenchmarkFeInvert(b *testing.B) {
	x, _ := benchFeOperands()
	for i := 0; i < b.N; i++ {
		feInvert(&x, &x)
	}
}

func BenchmarkScalarInvert(b *testing.B) {
	x := [4]uint64{1, 2, 3, 4}
	for i := 0; i < b.N; i++ {
		scalarInvert(&x, &x)
	}
}

func BenchmarkJacDouble(b *testing.B) {
	p := benchPoint()
	for i := 0; i < b.N; i++ {
		jacDouble(&p, &p)
	}
}

func BenchmarkJacAddConst(b *testing.B) {
	p := benchPoint()
	var q jacPoint
	jacDouble(&q, &p)
	for i := 0; i < b.N; i++ {
		jacAddConst(&p, &p, &q)
	}
}

func BenchmarkBaseTables(b *testing.B) {
	for i := 0; i < b.N; i++ {
		newBaseTables()
	}
}

func BenchmarkSM4Block(b *testing.B) {
	s := NewSM4()
	s.SetKey(benchData(16), benchData(16))
	x0, x1, x2, x3 := uint32(1), uint32(2), uint32(3), uint32(4)
	b.SetBytes(16)
	for i := 0; i < b.N; i++ {
		x0, x1, x2, x3 = sm4EncryptWords(&s.rk, x0, x1, x2, x3)
	}
	sinkString = string(rune(x0 ^ x1 ^ x2 ^ x3))
}

func BenchmarkSM3Block(b *testing.B) {
	data := benchData(sm3BlockSize)
	v := sm3IV
	b.SetBytes(sm3BlockSize)
	for i := 0; i < b.N; i++ {
		sm3Blocks(&v, data)
	}
}
