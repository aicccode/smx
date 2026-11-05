//go:build !amd64 || purego

package smx

// sm4CBCEncrypt encrypts whole blocks of buf in place.
func sm4CBCEncrypt(rk *[32]uint32, iv *[16]byte, buf []byte) {
	sm4CBCEncryptGeneric(rk, iv, buf)
}

// sm4CBCDecrypt decrypts whole blocks of buf in place.
func sm4CBCDecrypt(drk *[32]uint32, iv *[16]byte, buf []byte) {
	sm4CBCDecryptGeneric(drk, iv, buf)
}
