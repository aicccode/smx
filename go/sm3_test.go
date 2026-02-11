package smx

import "testing"

func TestSM3Abc(t *testing.T) {
	sm3 := NewSM3()
	sm3.Update([]byte("abc"))
	sm3.Finish()
	got := sm3.HashHexUpper()
	expected := "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0"
	if got != expected {
		t.Fatalf("SM3(abc) = %s, want %s", got, expected)
	}
}

func TestSM3Empty(t *testing.T) {
	sm3 := NewSM3()
	sm3.Update([]byte(""))
	sm3.Finish()
	got := sm3.HashHexUpper()
	expected := "1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B"
	if got != expected {
		t.Fatalf("SM3('') = %s, want %s", got, expected)
	}
}
