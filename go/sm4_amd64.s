//go:build amd64 && !purego

#include "textflag.h"

// SM4 in parallel using the AES instructions. The S-box is an affine transform of
// the AES S-box, so SubBytes does the non-linear work, and there are no secret-indexed
// memory accesses: this code is constant time with respect to the key and the data.
// S(x) = post(AES_SubBytes(pre(x))), with pre and post linear plus a constant, each
// done by two 4-bit lookups in a vector register. The constants are the ones published
// in the Linux kernel's sm4-aesni-avx-asm_64.S; the tests check them through the
// standard vectors, and sm4_amd64_test.go compares every path with the portable code.

DATA sm4PreLo<>+0(SB)/8, $0x9197E2E474720701
DATA sm4PreLo<>+8(SB)/8, $0xC7C1B4B222245157
GLOBL sm4PreLo<>(SB), RODATA|NOPTR, $16

DATA sm4PreHi<>+0(SB)/8, $0xE240AB09EB49A200
DATA sm4PreHi<>+8(SB)/8, $0xF052B91BF95BB012
GLOBL sm4PreHi<>(SB), RODATA|NOPTR, $16

DATA sm4PostLo<>+0(SB)/8, $0x5B67F2CEA19D0834
DATA sm4PostLo<>+8(SB)/8, $0xEDD14478172BBE82
GLOBL sm4PostLo<>(SB), RODATA|NOPTR, $16

DATA sm4PostHi<>+0(SB)/8, $0xAE7201DD73AFDC00
DATA sm4PostHi<>+8(SB)/8, $0x11CDBE62CC1063BF
GLOBL sm4PostHi<>(SB), RODATA|NOPTR, $16

// Inverse ShiftRows, on its own and combined with rotations left by 8, 16 and 24 bits.
DATA sm4InvShiftRow<>+0(SB)/8, $0x0B0E0104070A0D00
DATA sm4InvShiftRow<>+8(SB)/8, $0x0306090C0F020508
GLOBL sm4InvShiftRow<>(SB), RODATA|NOPTR, $16

DATA sm4InvShiftRowRol8<>+0(SB)/8, $0x0E01040B0A0D0007
DATA sm4InvShiftRowRol8<>+8(SB)/8, $0x06090C030205080F
GLOBL sm4InvShiftRowRol8<>(SB), RODATA|NOPTR, $16

DATA sm4InvShiftRowRol16<>+0(SB)/8, $0x01040B0E0D00070A
DATA sm4InvShiftRowRol16<>+8(SB)/8, $0x090C030605080F02
GLOBL sm4InvShiftRowRol16<>(SB), RODATA|NOPTR, $16

DATA sm4InvShiftRowRol24<>+0(SB)/8, $0x040B0E0100070A0D
DATA sm4InvShiftRowRol24<>+8(SB)/8, $0x0C030609080F0205
GLOBL sm4InvShiftRowRol24<>(SB), RODATA|NOPTR, $16

DATA sm4LowNibble<>+0(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA sm4LowNibble<>+8(SB)/8, $0x0F0F0F0F0F0F0F0F
GLOBL sm4LowNibble<>(SB), RODATA|NOPTR, $16

DATA sm4ByteSwap32<>+0(SB)/8, $0x0405060700010203
DATA sm4ByteSwap32<>+8(SB)/8, $0x0C0D0E0F08090A0B
GLOBL sm4ByteSwap32<>(SB), RODATA|NOPTR, $16

// Interleave four vectors of words, turning blocks into word slices or back.
#define TRANSPOSE(a, b, c, d, t0, t1, t2) \
	VPUNPCKHDQ b, a, t0;  \
	VPUNPCKLDQ b, a, a;   \
	VPUNPCKHDQ d, c, t1;  \
	VPUNPCKLDQ d, c, c;   \
	VPUNPCKHQDQ c, a, b;  \
	VPUNPCKLQDQ c, a, a;  \
	VPUNPCKHQDQ t1, t0, d; \
	VPUNPCKLQDQ t1, t0, c

// One SM4 round on word slices: s0 ^= L(S(s1 ^ s2 ^ s3 ^ rk)). x, t0 and t1 are
// scratch. Register roles for the constants are fixed by the LOADCONSTS macros.
#define ROUND(broadcast, rk, s0, s1, s2, s3, x, t0, t1, Mask, PreLo, PreHi, PostLo, PostHi, Inv, Rol8, Rol16, Rol24) \
	broadcast rk, x;             \
	VPXOR s1, x, x;              \
	VPXOR s2, x, x;              \
	VPXOR s3, x, x;              \
	VPAND Mask, x, t0;           \
	VPSRLD $4, x, t1;            \
	VPAND Mask, t1, t1;          \
	VPSHUFB t0, PreLo, t0;       \
	VPSHUFB t1, PreHi, t1;       \
	VPXOR t1, t0, x;             \
	VPXOR t1, t1, t1;            \
	VAESENCLAST t1, x, x;        \
	VPAND Mask, x, t0;           \
	VPSRLD $4, x, t1;            \
	VPAND Mask, t1, t1;          \
	VPSHUFB t0, PostLo, t0;      \
	VPSHUFB t1, PostHi, t1;      \
	VPXOR t1, t0, x;             \
	VPSHUFB Inv, x, t0;          \
	VPXOR t0, s0, s0;            \
	VPSHUFB Rol8, x, t1;         \
	VPXOR t1, t0, t0;            \
	VPSHUFB Rol16, x, t1;        \
	VPXOR t1, t0, t0;            \
	VPSHUFB Rol24, x, t1;        \
	VPXOR t1, s0, s0;            \
	VPSLLD $2, t0, t1;           \
	VPSRLD $30, t0, t0;          \
	VPXOR t0, s0, s0;            \
	VPXOR t1, s0, s0

#define ROUNDX_MEM(off, s0, s1, s2, s3) \
	ROUND(VBROADCASTSS, off(AX), s0, s1, s2, s3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, sm4InvShiftRowRol24<>(SB))

#define ROUNDY_MEM(off, s0, s1, s2, s3) \
	ROUND(VPBROADCASTD, off(AX), s0, s1, s2, s3, Y4, Y5, Y6, Y7, Y8, Y9, Y10, Y11, Y12, Y13, Y14, sm4InvShiftRowRol24Y<>(SB))

// func sm4Crypt4AVX(rk *[32]uint32, dst, src *byte)
// Runs the SM4 rounds over four 16-byte blocks; dst and src may be equal.
TEXT ·sm4Crypt4AVX(SB), NOSPLIT, $0-24
	MOVQ rk+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ src+16(FP), SI

	VMOVDQU sm4LowNibble<>(SB), X7
	VMOVDQU sm4PreLo<>(SB), X8
	VMOVDQU sm4PreHi<>(SB), X9
	VMOVDQU sm4PostLo<>(SB), X10
	VMOVDQU sm4PostHi<>(SB), X11
	VMOVDQU sm4InvShiftRow<>(SB), X12
	VMOVDQU sm4InvShiftRowRol8<>(SB), X13
	VMOVDQU sm4InvShiftRowRol16<>(SB), X14
	VMOVDQU sm4ByteSwap32<>(SB), X6

	VMOVDQU 0(SI), X0
	VMOVDQU 16(SI), X1
	VMOVDQU 32(SI), X2
	VMOVDQU 48(SI), X3
	VPSHUFB X6, X0, X0
	VPSHUFB X6, X1, X1
	VPSHUFB X6, X2, X2
	VPSHUFB X6, X3, X3
	TRANSPOSE(X0, X1, X2, X3, X4, X5, X6)

	MOVQ $8, CX

loop4:
	ROUNDX_MEM(0, X0, X1, X2, X3)
	ROUNDX_MEM(4, X1, X2, X3, X0)
	ROUNDX_MEM(8, X2, X3, X0, X1)
	ROUNDX_MEM(12, X3, X0, X1, X2)
	ADDQ $16, AX
	DECQ CX
	JNZ  loop4

	// The output order is reversed: X3, X2, X1, X0.
	TRANSPOSE(X3, X2, X1, X0, X4, X5, X6)
	VMOVDQU sm4ByteSwap32<>(SB), X6
	VPSHUFB X6, X3, X3
	VPSHUFB X6, X2, X2
	VPSHUFB X6, X1, X1
	VPSHUFB X6, X0, X0
	VMOVDQU X3, 0(DI)
	VMOVDQU X2, 16(DI)
	VMOVDQU X1, 32(DI)
	VMOVDQU X0, 48(DI)
	RET

DATA sm4InvShiftRowRol24Y<>+0(SB)/8, $0x040B0E0100070A0D
DATA sm4InvShiftRowRol24Y<>+8(SB)/8, $0x0C030609080F0205
DATA sm4InvShiftRowRol24Y<>+16(SB)/8, $0x040B0E0100070A0D
DATA sm4InvShiftRowRol24Y<>+24(SB)/8, $0x0C030609080F0205
GLOBL sm4InvShiftRowRol24Y<>(SB), RODATA|NOPTR, $32

// func sm4Crypt8VAES(rk *[32]uint32, dst, src *byte)
// Runs the SM4 rounds over eight 16-byte blocks; dst and src may be equal.
TEXT ·sm4Crypt8VAES(SB), NOSPLIT, $0-24
	MOVQ rk+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ src+16(FP), SI

	VBROADCASTI128 sm4LowNibble<>(SB), Y7
	VBROADCASTI128 sm4PreLo<>(SB), Y8
	VBROADCASTI128 sm4PreHi<>(SB), Y9
	VBROADCASTI128 sm4PostLo<>(SB), Y10
	VBROADCASTI128 sm4PostHi<>(SB), Y11
	VBROADCASTI128 sm4InvShiftRow<>(SB), Y12
	VBROADCASTI128 sm4InvShiftRowRol8<>(SB), Y13
	VBROADCASTI128 sm4InvShiftRowRol16<>(SB), Y14
	VBROADCASTI128 sm4ByteSwap32<>(SB), Y6

	VMOVDQU 0(SI), Y0
	VMOVDQU 32(SI), Y1
	VMOVDQU 64(SI), Y2
	VMOVDQU 96(SI), Y3
	VPSHUFB Y6, Y0, Y0
	VPSHUFB Y6, Y1, Y1
	VPSHUFB Y6, Y2, Y2
	VPSHUFB Y6, Y3, Y3
	TRANSPOSE(Y0, Y1, Y2, Y3, Y4, Y5, Y6)

	MOVQ $8, CX

loop8:
	ROUNDY_MEM(0, Y0, Y1, Y2, Y3)
	ROUNDY_MEM(4, Y1, Y2, Y3, Y0)
	ROUNDY_MEM(8, Y2, Y3, Y0, Y1)
	ROUNDY_MEM(12, Y3, Y0, Y1, Y2)
	ADDQ $16, AX
	DECQ CX
	JNZ  loop8

	TRANSPOSE(Y3, Y2, Y1, Y0, Y4, Y5, Y6)
	VBROADCASTI128 sm4ByteSwap32<>(SB), Y6
	VPSHUFB Y6, Y3, Y3
	VPSHUFB Y6, Y2, Y2
	VPSHUFB Y6, Y1, Y1
	VPSHUFB Y6, Y0, Y0
	VMOVDQU Y3, 0(DI)
	VMOVDQU Y2, 32(DI)
	VMOVDQU Y1, 64(DI)
	VMOVDQU Y0, 96(DI)
	VZEROUPPER
	RET

// GFNI computes the same S-box directly: S(x) = M2(inv(M1*x + 0x01)) + 0xD3 in the
// AES field. M2 already includes the AES affine step, so VGF2P8AFFINEINVQB does it all.
DATA sm4GFNIPre<>+0(SB)/8, $0x669B0D608A162E14
DATA sm4GFNIPre<>+8(SB)/8, $0x669B0D608A162E14
GLOBL sm4GFNIPre<>(SB), RODATA|NOPTR, $16

DATA sm4GFNIPost<>+0(SB)/8, $0x598EDB70229CA40E
DATA sm4GFNIPost<>+8(SB)/8, $0x598EDB70229CA40E
GLOBL sm4GFNIPost<>(SB), RODATA|NOPTR, $16

DATA sm4Rol8<>+0(SB)/8, $0x0605040702010003
DATA sm4Rol8<>+8(SB)/8, $0x0E0D0C0F0A09080B
GLOBL sm4Rol8<>(SB), RODATA|NOPTR, $16

DATA sm4Rol16<>+0(SB)/8, $0x0504070601000302
DATA sm4Rol16<>+8(SB)/8, $0x0D0C0F0E09080B0A
GLOBL sm4Rol16<>(SB), RODATA|NOPTR, $16

DATA sm4Rol24<>+0(SB)/8, $0x0407060500030201
DATA sm4Rol24<>+8(SB)/8, $0x0C0F0E0D080B0A09
GLOBL sm4Rol24<>(SB), RODATA|NOPTR, $16

#define ROUND_GFNI(broadcast, rk, s0, s1, s2, s3, x, t0, t1, Pre, Post, Rol8, Rol16, Rol24) \
	broadcast rk, x;                     \
	VPXOR s1, x, x;                      \
	VPXOR s2, x, x;                      \
	VPXOR s3, x, x;                      \
	VGF2P8AFFINEQB $0x01, Pre, x, x;     \
	VGF2P8AFFINEINVQB $0xD3, Post, x, x; \
	VPXOR x, s0, s0;                     \
	VPSHUFB Rol24, x, t1;                \
	VPXOR t1, s0, s0;                    \
	VPSHUFB Rol8, x, t0;                 \
	VPXOR x, t0, t0;                     \
	VPSHUFB Rol16, x, t1;                \
	VPXOR t1, t0, t0;                    \
	VPSLLD $2, t0, t1;                   \
	VPSRLD $30, t0, t0;                  \
	VPXOR t0, s0, s0;                    \
	VPXOR t1, s0, s0

#define ROUND_GFNI_X(off, s0, s1, s2, s3) \
	ROUND_GFNI(VBROADCASTSS, off(AX), s0, s1, s2, s3, X4, X5, X6, X7, X8, X9, X10, X11)

#define ROUND_GFNI_Y(off, s0, s1, s2, s3) \
	ROUND_GFNI(VPBROADCASTD, off(AX), s0, s1, s2, s3, Y4, Y5, Y6, Y7, Y8, Y9, Y10, Y11)

// func sm4Crypt4GFNI(rk *[32]uint32, dst, src *byte)
TEXT ·sm4Crypt4GFNI(SB), NOSPLIT, $0-24
	MOVQ rk+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ src+16(FP), SI

	VMOVDQU sm4GFNIPre<>(SB), X7
	VMOVDQU sm4GFNIPost<>(SB), X8
	VMOVDQU sm4Rol8<>(SB), X9
	VMOVDQU sm4Rol16<>(SB), X10
	VMOVDQU sm4Rol24<>(SB), X11
	VMOVDQU sm4ByteSwap32<>(SB), X12

	VMOVDQU 0(SI), X0
	VMOVDQU 16(SI), X1
	VMOVDQU 32(SI), X2
	VMOVDQU 48(SI), X3
	VPSHUFB X12, X0, X0
	VPSHUFB X12, X1, X1
	VPSHUFB X12, X2, X2
	VPSHUFB X12, X3, X3
	TRANSPOSE(X0, X1, X2, X3, X4, X5, X6)

	MOVQ $8, CX

loop4gfni:
	ROUND_GFNI_X(0, X0, X1, X2, X3)
	ROUND_GFNI_X(4, X1, X2, X3, X0)
	ROUND_GFNI_X(8, X2, X3, X0, X1)
	ROUND_GFNI_X(12, X3, X0, X1, X2)
	ADDQ $16, AX
	DECQ CX
	JNZ  loop4gfni

	TRANSPOSE(X3, X2, X1, X0, X4, X5, X6)
	VPSHUFB X12, X3, X3
	VPSHUFB X12, X2, X2
	VPSHUFB X12, X1, X1
	VPSHUFB X12, X0, X0
	VMOVDQU X3, 0(DI)
	VMOVDQU X2, 16(DI)
	VMOVDQU X1, 32(DI)
	VMOVDQU X0, 48(DI)
	RET

// func sm4Crypt8GFNI(rk *[32]uint32, dst, src *byte)
TEXT ·sm4Crypt8GFNI(SB), NOSPLIT, $0-24
	MOVQ rk+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ src+16(FP), SI

	VBROADCASTI128 sm4GFNIPre<>(SB), Y7
	VBROADCASTI128 sm4GFNIPost<>(SB), Y8
	VBROADCASTI128 sm4Rol8<>(SB), Y9
	VBROADCASTI128 sm4Rol16<>(SB), Y10
	VBROADCASTI128 sm4Rol24<>(SB), Y11
	VBROADCASTI128 sm4ByteSwap32<>(SB), Y12

	VMOVDQU 0(SI), Y0
	VMOVDQU 32(SI), Y1
	VMOVDQU 64(SI), Y2
	VMOVDQU 96(SI), Y3
	VPSHUFB Y12, Y0, Y0
	VPSHUFB Y12, Y1, Y1
	VPSHUFB Y12, Y2, Y2
	VPSHUFB Y12, Y3, Y3
	TRANSPOSE(Y0, Y1, Y2, Y3, Y4, Y5, Y6)

	MOVQ $8, CX

loop8gfni:
	ROUND_GFNI_Y(0, Y0, Y1, Y2, Y3)
	ROUND_GFNI_Y(4, Y1, Y2, Y3, Y0)
	ROUND_GFNI_Y(8, Y2, Y3, Y0, Y1)
	ROUND_GFNI_Y(12, Y3, Y0, Y1, Y2)
	ADDQ $16, AX
	DECQ CX
	JNZ  loop8gfni

	TRANSPOSE(Y3, Y2, Y1, Y0, Y4, Y5, Y6)
	VPSHUFB Y12, Y3, Y3
	VPSHUFB Y12, Y2, Y2
	VPSHUFB Y12, Y1, Y1
	VPSHUFB Y12, Y0, Y0
	VMOVDQU Y3, 0(DI)
	VMOVDQU Y2, 32(DI)
	VMOVDQU Y1, 64(DI)
	VMOVDQU Y0, 96(DI)
	VZEROUPPER
	RET

// func cpuid(leaf, subleaf uint32) (eax, ebx, ecx, edx uint32)
TEXT ·cpuid(SB), NOSPLIT, $0-24
	MOVL leaf+0(FP), AX
	MOVL subleaf+4(FP), CX
	CPUID
	MOVL AX, eax+8(FP)
	MOVL BX, ebx+12(FP)
	MOVL CX, ecx+16(FP)
	MOVL DX, edx+20(FP)
	RET

// func xgetbv() (eax, edx uint32)
TEXT ·xgetbv(SB), NOSPLIT, $0-8
	XORL CX, CX
	XGETBV
	MOVL AX, eax+0(FP)
	MOVL DX, edx+4(FP)
	RET
