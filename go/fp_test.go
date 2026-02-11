package smx

import "testing"

func TestFpAdd(t *testing.T) {
	a := FpFromHex("1")
	b := FpFromHex("2")
	c := a.Add(b)
	expected := BigInt256FromHex("3")
	if c.value != expected {
		t.Fatalf("got %s", c.ToHex())
	}
}

func TestFpSub(t *testing.T) {
	a := FpFromHex("5")
	b := FpFromHex("3")
	c := a.Sub(b)
	expected := BigInt256FromHex("2")
	if c.value != expected {
		t.Fatalf("got %s", c.ToHex())
	}
}

func TestFpMul(t *testing.T) {
	a := FpFromHex("3")
	b := FpFromHex("4")
	c := a.Mul(b)
	expected := BigInt256FromHex("C")
	if c.value != expected {
		t.Fatalf("got %s", c.ToHex())
	}
}

func TestFpInvert(t *testing.T) {
	a := FpFromHex("3")
	inv := a.Invert()
	product := a.Mul(inv)
	if !product.IsOne() {
		t.Fatalf("expected 1, got %s", product.ToHex())
	}
}

func TestFpNegate(t *testing.T) {
	a := FpFromHex("1")
	neg := a.Negate()
	sum := a.Add(neg)
	if !sum.IsZero() {
		t.Fatalf("expected 0, got %s", sum.ToHex())
	}
}
