package smx

import "testing"

func TestSM4EncryptDecrypt(t *testing.T) {
	key := "this is the key"
	iv := "this is the iv"

	sm4 := NewSM4()
	sm4.SetKey([]byte(key), []byte(iv))

	plaintext := "国密SM4对称加密算法"

	ciphertext, err := sm4.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	expectedCiphertext := "09908004c24cece806ee6dc2d6a3d154907048fb96d0201a8c47f4f1e03995bc"
	if ciphertext != expectedCiphertext {
		t.Fatalf("ciphertext = %s, want %s", ciphertext, expectedCiphertext)
	}

	decrypted, err := sm4.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if decrypted != plaintext {
		t.Fatalf("decrypted = %s, want %s", decrypted, plaintext)
	}
}
