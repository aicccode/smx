package smx

import "fmt"

var sm4SBox = [256]byte{
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
}

var sm4FK = [4]uint32{0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc}

var sm4CK = [32]uint32{
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
}

// SM4 implements the SM4 block cipher with CBC mode and PKCS#7 padding.
type SM4 struct {
	rk [32]uint32
	iv [16]byte
}

// NewSM4 creates a new SM4 instance.
func NewSM4() *SM4 {
	return &SM4{}
}

// SetKey sets the encryption key and IV. Non-16-byte keys/IVs are hashed via SM3.
func (s *SM4) SetKey(key, iv []byte) {
	keyBytes := sm4PrepareKey(key)
	ivBytes := sm4PrepareKey(iv)
	s.initKey(keyBytes, ivBytes)
}

func sm4PrepareKey(input []byte) [16]byte {
	if len(input) == 16 {
		var out [16]byte
		copy(out[:], input)
		return out
	}
	h := NewSM3()
	h.Update(input)
	h.Finish()
	hexStr := h.HashHexUpper()
	var out [16]byte
	copy(out[:], hexStr[:16])
	return out
}

func (s *SM4) initKey(key [16]byte, iv [16]byte) {
	var mk [4]uint32
	for i := 0; i < 4; i++ {
		mk[i] = uint32(key[i*4])<<24 | uint32(key[i*4+1])<<16 |
			uint32(key[i*4+2])<<8 | uint32(key[i*4+3])
	}

	var k [36]uint32
	k[0] = mk[0] ^ sm4FK[0]
	k[1] = mk[1] ^ sm4FK[1]
	k[2] = mk[2] ^ sm4FK[2]
	k[3] = mk[3] ^ sm4FK[3]

	for i := 0; i < 32; i++ {
		input := k[i+1] ^ k[i+2] ^ k[i+3] ^ sm4CK[i]
		k[i+4] = k[i] ^ sm4TPrime(input)
		s.rk[i] = k[i+4]
	}

	s.iv = iv
}

func sm4Tau(a uint32) uint32 {
	b0 := sm4SBox[byte(a>>24)]
	b1 := sm4SBox[byte(a>>16)]
	b2 := sm4SBox[byte(a>>8)]
	b3 := sm4SBox[byte(a)]
	return uint32(b0)<<24 | uint32(b1)<<16 | uint32(b2)<<8 | uint32(b3)
}

func sm4L(b uint32) uint32 {
	return b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24)
}

func sm4T(a uint32) uint32 {
	return sm4L(sm4Tau(a))
}

func sm4TPrime(a uint32) uint32 {
	b := sm4Tau(a)
	return b ^ rotl32(b, 13) ^ rotl32(b, 23)
}

func rotl32(x uint32, n int) uint32 {
	return (x << n) | (x >> (32 - n))
}

func sm4F(x0, x1, x2, x3, rk uint32) uint32 {
	return x0 ^ sm4T(x1^x2^x3^rk)
}

// Encrypt encrypts a plaintext string and returns ciphertext as hex.
func (s *SM4) Encrypt(plaintext string) (string, error) {
	input := []byte(plaintext)
	padded := pkcs7Pad(input)
	iv := s.iv
	var output []byte

	for i := 0; i < len(padded); i += 16 {
		block := padded[i : i+16]
		encrypted := s.cbcEncryptBlock(block, iv[:])
		output = append(output, encrypted[:]...)
		iv = encrypted
	}

	return bytesToHex(output), nil
}

// Decrypt decrypts a hex ciphertext string and returns plaintext.
func (s *SM4) Decrypt(ciphertext string) (string, error) {
	input, err := hexToBytes(ciphertext)
	if err != nil {
		return "", err
	}
	if len(input)%16 != 0 {
		return "", fmt.Errorf("invalid ciphertext length")
	}

	iv := s.iv
	var output []byte

	for i := 0; i < len(input); i += 16 {
		block := input[i : i+16]
		decrypted := s.cbcDecryptBlock(block, iv[:])
		output = append(output, decrypted[:]...)
		copy(iv[:], block)
	}

	unpadded, err := pkcs7Unpad(output)
	if err != nil {
		return "", err
	}
	return string(unpadded), nil
}

func (s *SM4) cbcEncryptBlock(block, iv []byte) [16]byte {
	var x [4]uint32
	for i := 0; i < 4; i++ {
		x[i] = uint32(block[i*4])<<24 | uint32(block[i*4+1])<<16 |
			uint32(block[i*4+2])<<8 | uint32(block[i*4+3])
		ivWord := uint32(iv[i*4])<<24 | uint32(iv[i*4+1])<<16 |
			uint32(iv[i*4+2])<<8 | uint32(iv[i*4+3])
		x[i] ^= ivWord
	}

	var xn [36]uint32
	copy(xn[:4], x[:])
	for i := 0; i < 32; i++ {
		xn[i+4] = sm4F(xn[i], xn[i+1], xn[i+2], xn[i+3], s.rk[i])
	}

	// Reverse
	xo := [4]uint32{xn[35], xn[34], xn[33], xn[32]}

	var out [16]byte
	for i := 0; i < 4; i++ {
		out[i*4] = byte(xo[i] >> 24)
		out[i*4+1] = byte(xo[i] >> 16)
		out[i*4+2] = byte(xo[i] >> 8)
		out[i*4+3] = byte(xo[i])
	}
	return out
}

func (s *SM4) cbcDecryptBlock(block, iv []byte) [16]byte {
	var x [4]uint32
	for i := 0; i < 4; i++ {
		x[i] = uint32(block[i*4])<<24 | uint32(block[i*4+1])<<16 |
			uint32(block[i*4+2])<<8 | uint32(block[i*4+3])
	}

	var xn [36]uint32
	copy(xn[:4], x[:])
	for i := 0; i < 32; i++ {
		xn[i+4] = sm4F(xn[i], xn[i+1], xn[i+2], xn[i+3], s.rk[31-i])
	}

	xo := [4]uint32{xn[35], xn[34], xn[33], xn[32]}

	var out [16]byte
	for i := 0; i < 4; i++ {
		b := [4]byte{byte(xo[i] >> 24), byte(xo[i] >> 16), byte(xo[i] >> 8), byte(xo[i])}
		out[i*4] = b[0] ^ iv[i*4]
		out[i*4+1] = b[1] ^ iv[i*4+1]
		out[i*4+2] = b[2] ^ iv[i*4+2]
		out[i*4+3] = b[3] ^ iv[i*4+3]
	}
	return out
}

func pkcs7Pad(input []byte) []byte {
	padLen := 16 - (len(input) % 16)
	if padLen == 0 {
		padLen = 16
	}
	out := make([]byte, len(input)+padLen)
	copy(out, input)
	for i := len(input); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out
}

func pkcs7Unpad(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}
	padLen := int(input[len(input)-1])
	if padLen == 0 || padLen > 16 || padLen > len(input) {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(input) - padLen; i < len(input); i++ {
		if int(input[i]) != padLen {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return input[:len(input)-padLen], nil
}
