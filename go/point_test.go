package smx

import "testing"

func TestGeneratorOnCurve(t *testing.T) {
	g := ECPointGenerator()
	if !g.IsOnCurve() {
		t.Fatal("generator not on curve")
	}
}

func TestPointAdd(t *testing.T) {
	g := ECPointGenerator()
	g2 := g.Add(g)
	if !g2.IsOnCurve() {
		t.Fatal("2G not on curve")
	}
	g3 := g2.Add(g)
	if !g3.IsOnCurve() {
		t.Fatal("3G not on curve")
	}
}

func TestPointTwice(t *testing.T) {
	g := ECPointGenerator()
	g2a := g.Twice()
	g2b := g.Add(g)
	if !g2a.Equal(g2b) {
		t.Fatal("Twice != Add(self)")
	}
}

func TestPointMultiply(t *testing.T) {
	g := ECPointGenerator()
	k := BigInt256FromHex("3")
	p := g.Multiply(&k)
	if !p.IsOnCurve() {
		t.Fatal("3G not on curve")
	}

	g2 := g.Twice()
	g3 := g2.Add(g)
	if !p.Equal(g3) {
		t.Fatal("Multiply(3) != Twice+Add")
	}
}

func TestPointEncodeDecode(t *testing.T) {
	g := ECPointGenerator()
	encoded := g.ToEncoded()
	decoded := ECPointFromEncoded(encoded)
	if !g.Equal(decoded) {
		t.Fatal("encode/decode mismatch")
	}
}

func TestInfinity(t *testing.T) {
	g := ECPointGenerator()
	negG := g.Negate()
	result := g.Add(negG)
	if !result.Infinity {
		t.Fatal("G + (-G) should be infinity")
	}
}
