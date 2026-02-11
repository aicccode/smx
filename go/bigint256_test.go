package smx

import "testing"

func TestFromHex(t *testing.T) {
	n := BigInt256FromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF")
	if n.ToHex() != "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF" {
		t.Fatalf("got %s", n.ToHex())
	}
}

func TestAdd(t *testing.T) {
	a := BigInt256FromHex("1")
	b := BigInt256FromHex("2")
	c, _ := a.Add(&b)
	if c.ToHex() != "0000000000000000000000000000000000000000000000000000000000000003" {
		t.Fatalf("got %s", c.ToHex())
	}
}

func TestSub(t *testing.T) {
	a := BigInt256FromHex("5")
	b := BigInt256FromHex("3")
	c, _ := a.Sub(&b)
	if c.ToHex() != "0000000000000000000000000000000000000000000000000000000000000002" {
		t.Fatalf("got %s", c.ToHex())
	}
}

func TestMul(t *testing.T) {
	a := BigInt256FromHex("3")
	b := BigInt256FromHex("4")
	p := BigInt256FromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF")
	c := a.ModMul(&b, &p)
	if c.ToHex() != "000000000000000000000000000000000000000000000000000000000000000C" {
		t.Fatalf("got %s", c.ToHex())
	}
}

func TestModInverse(t *testing.T) {
	a := BigInt256FromHex("3")
	p := BigInt256FromHex("7")
	inv := a.ModInverse(&p)
	product := a.ModMul(&inv, &p)
	if !product.IsOne() {
		t.Fatalf("expected 1, got %s", product.ToHex())
	}
}
