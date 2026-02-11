package smx

import (
	"encoding/hex"
	"strings"
)

// bytesToHex converts a byte slice to a lowercase hex string.
func bytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

// hexToBytes converts a hex string to a byte slice.
func hexToBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return hex.DecodeString(s)
}
