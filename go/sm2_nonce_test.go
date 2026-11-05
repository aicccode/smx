package smx

import "testing"

// With the nonce fixed, encryption and signing must produce the exact bytes captured
// from the pre-optimization implementation.

func TestSM2EncryptMatchesCaptured(t *testing.T) {
	for _, tc := range katSM2Encrypt {
		d := BigInt256FromHex(tc.d)
		k := BigInt256FromHex(tc.k)
		pub := SM2GetPublicKey(&d)
		got, ok := sm2EncryptWithNonce(string(kattern(tc.n)), &pub, &k)
		if !ok || got != tc.want {
			t.Errorf("d=%s k=%s n=%d:\n got %s\nwant %s", tc.d, tc.k, tc.n, got, tc.want)
		}
	}
}

func TestSM2SignMatchesCaptured(t *testing.T) {
	for _, tc := range katSM2Sign {
		d := BigInt256FromHex(tc.d)
		k := BigInt256FromHex(tc.k)
		got, ok := sm2SignWithNonce(tc.id, tc.msg, &d, &k)
		if !ok || got != tc.want {
			t.Errorf("d=%s k=%s id=%q:\n got %s\nwant %s", tc.d, tc.k, tc.id, got, tc.want)
		}
	}
}

// GB/T 32918.5 appendix: signing with the published key and nonce gives the published (r, s).
func TestSM2SignStandardVector(t *testing.T) {
	d := BigInt256FromHex(gbtPrivateKey)
	k := BigInt256FromHex(gbtNonce)
	got, ok := sm2SignWithNonce("1234567812345678", "message digest", &d, &k)
	if !ok || got != gbtSignature {
		t.Errorf("got %s, want %s", got, gbtSignature)
	}
}

// GB/T 32918.5 appendix: encrypting with the published key and nonce gives the published ciphertext.
func TestSM2EncryptStandardVector(t *testing.T) {
	d := BigInt256FromHex(gbtPrivateKey)
	k := BigInt256FromHex(gbtNonce)
	pub := SM2GetPublicKey(&d)
	got, ok := sm2EncryptWithNonce("encryption standard", &pub, &k)
	if !ok || got != gbtCiphertext {
		t.Errorf("got %s, want %s", got, gbtCiphertext)
	}
}
