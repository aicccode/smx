package smx

import "testing"

func TestKeyPairGeneration(t *testing.T) {
	pri, pub := SM2GenKeyPair()
	if len(pri) != 64 {
		t.Fatalf("private key length = %d, want 64", len(pri))
	}
	if len(pub) != 130 {
		t.Fatalf("public key length = %d, want 130", len(pub))
	}
	if pub[:2] != "04" {
		t.Fatalf("public key should start with 04")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	pri, pub := SM2GenKeyPair()
	message := "encryption standard"

	encrypted, err := SM2Encrypt(message, pub)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := SM2Decrypt(encrypted, pri)
	if err != nil {
		t.Fatal(err)
	}

	if decrypted != message {
		t.Fatalf("decrypted = %s, want %s", decrypted, message)
	}
}

func TestSignVerify(t *testing.T) {
	pri, pub := SM2GenKeyPair()
	userID := "ALICE123@YAHOO.COM"
	message := "encryption standard"

	signature, err := SM2Sign(userID, message, pri)
	if err != nil {
		t.Fatal(err)
	}

	valid := SM2Verify(userID, signature, message, pub)
	if !valid {
		t.Fatal("signature should be valid")
	}
}

func TestSignVerifyWrongMessage(t *testing.T) {
	pri, pub := SM2GenKeyPair()
	userID := "ALICE123@YAHOO.COM"
	message := "encryption standard"

	signature, err := SM2Sign(userID, message, pri)
	if err != nil {
		t.Fatal(err)
	}

	valid := SM2Verify(userID, signature, "wrong message", pub)
	if valid {
		t.Fatal("signature should be invalid for wrong message")
	}
}

func TestKeyExchange(t *testing.T) {
	idA := "ALICE123@YAHOO.COM"
	idB := "BILL456@YAHOO.COM"

	dA := BigInt256FromHex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE")
	pA := SM2GetPublicKey(&dA)

	ra := BigInt256FromHex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563")
	rA := SM2GetPublicKey(&ra)

	dB := BigInt256FromHex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53")
	pB := SM2GetPublicKey(&dB)

	rb := BigInt256FromHex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80")
	rB := SM2GetPublicKey(&rb)

	resultB := SM2GetSb(16, pA, rA, pB, &dB, rB, &rb, idA, idB)
	if !resultB.Success {
		t.Fatalf("B key exchange failed: %s", resultB.Message)
	}

	sbBytes, _ := hexToBytes(resultB.Sb)
	resultA := SM2GetSa(16, pB, rB, pA, &dA, rA, &ra, idA, idB, sbBytes)
	if !resultA.Success {
		t.Fatalf("A key exchange failed: %s", resultA.Message)
	}

	if resultA.Ka != resultB.Kb {
		t.Fatalf("Ka != Kb: %s != %s", resultA.Ka, resultB.Kb)
	}

	saBytes, _ := hexToBytes(resultA.Sa)
	check := SM2CheckSa(*resultB.V, resultB.Za, resultB.Zb, rA, rB, saBytes)
	if !check {
		t.Fatal("B failed to verify Sa")
	}
}

func TestUserSM3Z(t *testing.T) {
	userID := "ALICE123@YAHOO.COM"
	_, pub := SM2GenKeyPair()
	point := SM2DecodePoint(pub)
	z := userSM3Z([]byte(userID), point)
	if len(z) != 32 {
		t.Fatalf("Z length = %d, want 32", len(z))
	}
}
