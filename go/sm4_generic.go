//go:build !amd64 || purego

package smx

// sm4CBCDecrypt decrypts whole blocks of buf in place. Without the amd64 vector code the
// interleaved table rounds are the fastest choice for every length; on an Apple M2 they
// beat the bitsliced batch the constant-time version uses by about four times.
func sm4CBCDecrypt(drk *[32]uint32, iv *[16]byte, buf []byte) {
	sm4CBCDecryptTable(drk, iv, buf)
}
