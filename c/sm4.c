#include "smx_internal.h"
#include <stdlib.h>
#include <string.h>

/*
 * SM4 in CBC mode with PKCS7 padding.
 *
 * Block implementations, picked once at load time from what the CPU reports:
 *   tier 3  GFNI + AVX2      8 blocks at a time, constant time
 *   tier 2  AES-NI + AVX2    8 blocks at a time, constant time
 *   tier 1  AES-NI + SSSE3   4 blocks at a time, constant time
 *   tier 0  portable C       1 block at a time, table lookups: see sm4_t_table
 *
 * CBC decryption is parallel and uses the full width. CBC encryption is
 * inherently serial, so it runs one block through the vector S-box, which costs
 * some speed against a table lookup but removes secret-indexed memory access.
 *
 * Define SMX_NO_SIMD to build only tier 0, or SMX_SM4_MAX_TIER to cap the tier;
 * `make check-fallbacks` runs the tests against every tier.
 */

#ifndef SMX_SM4_MAX_TIER
#define SMX_SM4_MAX_TIER 3
#endif

#if defined(__x86_64__) && !defined(SMX_NO_SIMD) &&                                                \
    (defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 8))
#define SMX_SM4_X86 1
#include <cpuid.h>
#include <immintrin.h>
#endif

static const uint8_t sm4_sbox[256] = {
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
};

static const uint32_t sm4_fk[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

static const uint32_t sm4_ck[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

/*
 * sm4_t_table[b] = L(S(b) << 24). The other byte positions are rotations of it,
 * since L commutes with rotation.
 *
 * Cache-timing caveat: this table is indexed by secret data, like the S-box it
 * replaces, but it is larger (1 KB instead of 256 bytes). An attacker sharing the
 * cache can learn key material from the access pattern. It is only used on the
 * portable path, where no hardware S-box is available; the x86 paths above do not
 * touch it.
 */
static const uint32_t sm4_t_table[256] = {
    0x8ED55B5B, 0xD0924242, 0x4DEAA7A7, 0x06FDFBFB, 0xFCCF3333, 0x65E28787, 0xC93DF4F4, 0x6BB5DEDE,
    0x4E165858, 0x6EB4DADA, 0x44145050, 0xCAC10B0B, 0x8828A0A0, 0x17F8EFEF, 0x9C2CB0B0, 0x11051414,
    0x872BACAC, 0xFB669D9D, 0xF2986A6A, 0xAE77D9D9, 0x822AA8A8, 0x46BCFAFA, 0x14041010, 0xCFC00F0F,
    0x02A8AAAA, 0x54451111, 0x5F134C4C, 0xBE269898, 0x6D482525, 0x9E841A1A, 0x1E061818, 0xFD9B6666,
    0xEC9E7272, 0x4A430909, 0x10514141, 0x24F7D3D3, 0xD5934646, 0x53ECBFBF, 0xF89A6262, 0x927BE9E9,
    0xFF33CCCC, 0x04555151, 0x270B2C2C, 0x4F420D0D, 0x59EEB7B7, 0xF3CC3F3F, 0x1CAEB2B2, 0xEA638989,
    0x74E79393, 0x7FB1CECE, 0x6C1C7070, 0x0DABA6A6, 0xEDCA2727, 0x28082020, 0x48EBA3A3, 0xC1975656,
    0x80820202, 0xA3DC7F7F, 0xC4965252, 0x12F9EBEB, 0xA174D5D5, 0xB38D3E3E, 0xC33FFCFC, 0x3EA49A9A,
    0x5B461D1D, 0x1B071C1C, 0x3BA59E9E, 0x0CFFF3F3, 0x3FF0CFCF, 0xBF72CDCD, 0x4B175C5C, 0x52B8EAEA,
    0x8F810E0E, 0x3D586565, 0xCC3CF0F0, 0x7D196464, 0x7EE59B9B, 0x91871616, 0x734E3D3D, 0x08AAA2A2,
    0xC869A1A1, 0xC76AADAD, 0x85830606, 0x7AB0CACA, 0xB570C5C5, 0xF4659191, 0xB2D96B6B, 0xA7892E2E,
    0x18FBE3E3, 0x47E8AFAF, 0x330F3C3C, 0x674A2D2D, 0xB071C1C1, 0x0E575959, 0xE99F7676, 0xE135D4D4,
    0x661E7878, 0xB4249090, 0x360E3838, 0x265F7979, 0xEF628D8D, 0x38596161, 0x95D24747, 0x2AA08A8A,
    0xB1259494, 0xAA228888, 0x8C7DF1F1, 0xD73BECEC, 0x05010404, 0xA5218484, 0x9879E1E1, 0x9B851E1E,
    0x84D75353, 0x00000000, 0x5E471919, 0x0B565D5D, 0xE39D7E7E, 0x9FD04F4F, 0xBB279C9C, 0x1A534949,
    0x7C4D3131, 0xEE36D8D8, 0x0A020808, 0x7BE49F9F, 0x20A28282, 0xD4C71313, 0xE8CB2323, 0xE69C7A7A,
    0x42E9ABAB, 0x43BDFEFE, 0xA2882A2A, 0x9AD14B4B, 0x40410101, 0xDBC41F1F, 0xD838E0E0, 0x61B7D6D6,
    0x2FA18E8E, 0x2BF4DFDF, 0x3AF1CBCB, 0xF6CD3B3B, 0x1DFAE7E7, 0xE5608585, 0x41155454, 0x25A38686,
    0x60E38383, 0x16ACBABA, 0x295C7575, 0x34A69292, 0xF7996E6E, 0xE434D0D0, 0x721A6868, 0x01545555,
    0x19AFB6B6, 0xDF914E4E, 0xFA32C8C8, 0xF030C0C0, 0x21F6D7D7, 0xBC8E3232, 0x75B3C6C6, 0x6FE08F8F,
    0x691D7474, 0x2EF5DBDB, 0x6AE18B8B, 0x962EB8B8, 0x8A800A0A, 0xFE679999, 0xE2C92B2B, 0xE0618181,
    0xC0C30303, 0x8D29A4A4, 0xAF238C8C, 0x07A9AEAE, 0x390D3434, 0x1F524D4D, 0x764F3939, 0xD36EBDBD,
    0x81D65757, 0xB7D86F6F, 0xEB37DCDC, 0x51441515, 0xA6DD7B7B, 0x09FEF7F7, 0xB68C3A3A, 0x932FBCBC,
    0x0F030C0C, 0x03FCFFFF, 0xC26BA9A9, 0xBA73C9C9, 0xD96CB5B5, 0xDC6DB1B1, 0x375A6D6D, 0x15504545,
    0xB98F3636, 0x771B6C6C, 0x13ADBEBE, 0xDA904A4A, 0x57B9EEEE, 0xA9DE7777, 0x4CBEF2F2, 0x837EFDFD,
    0x55114444, 0xBDDA6767, 0x2C5D7171, 0x45400505, 0x631F7C7C, 0x50104040, 0x325B6969, 0xB8DB6363,
    0x220A2828, 0xC5C20707, 0xF531C4C4, 0xA88A2222, 0x31A79696, 0xF9CE3737, 0x977AEDED, 0x49BFF6F6,
    0x992DB4B4, 0xA475D1D1, 0x90D34343, 0x5A124848, 0x58BAE2E2, 0x71E69797, 0x64B6D2D2, 0x70B2C2C2,
    0xAD8B2626, 0xCD68A5A5, 0xCB955E5E, 0x624B2929, 0x3C0C3030, 0xCE945A5A, 0xAB76DDDD, 0x867FF9F9,
    0xF1649595, 0x5DBBE6E6, 0x35F2C7C7, 0x2D092424, 0xD1C61717, 0xD66FB9B9, 0xDEC51B1B, 0x94861212,
    0x78186060, 0x30F3C3C3, 0x897CF5F5, 0x5CEFB3B3, 0xD23AE8E8, 0xACDF7373, 0x794C3535, 0xA0208080,
    0x9D78E5E5, 0x56EDBBBB, 0x235E7D7D, 0xC63EF8F8, 0x8BD45F5F, 0xE7C82F2F, 0xDD39E4E4, 0x68492121,
};

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/* ---- portable path ---- */

#define SM4_T(x)                                                                                   \
    (sm4_t_table[(x) >> 24] ^ ROR32(sm4_t_table[((x) >> 16) & 0xFF], 8) ^                          \
     ROR32(sm4_t_table[((x) >> 8) & 0xFF], 16) ^ ROR32(sm4_t_table[(x) & 0xFF], 24))

static inline void sm4_scalar_rounds(const uint32_t rk[32], uint32_t x[4]) {
    uint32_t a = x[0], b = x[1], c = x[2], d = x[3], t;
    int i;
    for (i = 0; i < 32; i += 4) {
        t = b ^ c ^ d ^ rk[i];
        a ^= SM4_T(t);
        t = c ^ d ^ a ^ rk[i + 1];
        b ^= SM4_T(t);
        t = d ^ a ^ b ^ rk[i + 2];
        c ^= SM4_T(t);
        t = a ^ b ^ c ^ rk[i + 3];
        d ^= SM4_T(t);
    }
    /* the final reversal */
    x[0] = d;
    x[1] = c;
    x[2] = b;
    x[3] = a;
}

static void sm4_scalar_blocks(const uint32_t rk[32], const uint8_t *in, uint8_t *out) {
    uint32_t x[4];
    int i;
    for (i = 0; i < 4; i++) {
        x[i] = smx_load_be32(in + i * 4);
    }
    sm4_scalar_rounds(rk, x);
    for (i = 0; i < 4; i++) {
        smx_store_be32(out + i * 4, x[i]);
    }
}

static void sm4_scalar_cbc_encrypt(const uint32_t rk[32], uint32_t iv[4], const uint8_t *in,
                                   size_t blocks, char *hex) {
    uint32_t x[4];
    uint8_t ct[16];
    int i;
    x[0] = iv[0];
    x[1] = iv[1];
    x[2] = iv[2];
    x[3] = iv[3];
    for (; blocks > 0; blocks--, in += 16, hex += 32) {
        for (i = 0; i < 4; i++) {
            x[i] ^= smx_load_be32(in + i * 4);
        }
        sm4_scalar_rounds(rk, x);
        for (i = 0; i < 4; i++) {
            smx_store_be32(ct + i * 4, x[i]);
        }
        smx_hex_encode(ct, 16, hex, 'a');
    }
    iv[0] = x[0];
    iv[1] = x[1];
    iv[2] = x[2];
    iv[3] = x[3];
}

/* ---- x86 paths ---- */

#ifdef SMX_SM4_X86

/* "unused": a lower SMX_SM4_MAX_TIER leaves the faster implementations unreferenced */
#define TARGET_AESNI128 __attribute__((target("ssse3,aes"), unused))
#define TARGET_AESNI256 __attribute__((target("avx2,aes"), unused))
#define TARGET_GFNI __attribute__((target("avx2,gfni"), unused))

/* S(x) = post(AES_inverse(pre(x))), found by matching the two fields' subfields */
#define GFNI_PRE 0x669B0D608A162E14LL
#define GFNI_PRE_C 0x01
#define GFNI_POST 0x598EDB70229CA40ELL
#define GFNI_POST_C 0xD3

#define BYTES16(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p)                                    \
    (char)(p), (char)(o), (char)(n), (char)(m), (char)(l), (char)(k), (char)(j), (char)(i),        \
        (char)(h), (char)(g), (char)(f), (char)(e), (char)(d), (char)(c), (char)(b), (char)(a)
#define BSWAP32_SHUFFLE BYTES16(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12)
#define ROL8_SHUFFLE BYTES16(3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14)
#define ROL16_SHUFFLE BYTES16(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13)
#define ROL24_SHUFFLE BYTES16(1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12)
/* undoes the ShiftRows inside aesenclast */
#define INV_SHIFT_ROWS BYTES16(0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3)
/* AES-NI affine maps around the S-box, as nibble lookups */
#define PRE_LO                                                                                     \
    BYTES16(0x01, 0x07, 0x72, 0x74, 0xE4, 0xE2, 0x97, 0x91, 0x57, 0x51, 0x24, 0x22, 0xB2, 0xB4,    \
            0xC1, 0xC7)
#define PRE_HI                                                                                     \
    BYTES16(0x00, 0xA2, 0x49, 0xEB, 0x09, 0xAB, 0x40, 0xE2, 0x12, 0xB0, 0x5B, 0xF9, 0x1B, 0xB9,    \
            0x52, 0xF0)
#define POST_LO                                                                                    \
    BYTES16(0x34, 0x08, 0x9D, 0xA1, 0xCE, 0xF2, 0x67, 0x5B, 0x82, 0xBE, 0x2B, 0x17, 0x78, 0x44,    \
            0xD1, 0xED)
#define POST_HI                                                                                    \
    BYTES16(0x00, 0xDC, 0xAF, 0x73, 0xDD, 0x01, 0x72, 0xAE, 0xBF, 0x63, 0x10, 0xCC, 0x62, 0xBE,    \
            0xCD, 0x11)

/*
 * The linear layer: x ^ rol(x, 24) ^ rol(x ^ rol(x, 8) ^ rol(x, 16), 2). A macro
 * because functions with different target attributes cannot inline one another.
 */
#define SM4_L_128_BODY                                                                             \
    const __m128i r8 = _mm_set_epi8(ROL8_SHUFFLE), r16 = _mm_set_epi8(ROL16_SHUFFLE);              \
    const __m128i r24 = _mm_set_epi8(ROL24_SHUFFLE);                                               \
    __m128i y =                                                                                    \
        _mm_xor_si128(_mm_xor_si128(x, _mm_shuffle_epi8(x, r8)), _mm_shuffle_epi8(x, r16));        \
    __m128i z = _mm_or_si128(_mm_slli_epi32(y, 2), _mm_srli_epi32(y, 30));                         \
    return _mm_xor_si128(_mm_xor_si128(x, _mm_shuffle_epi8(x, r24)), z);

TARGET_AESNI128 static inline __m128i sm4_aesni_sbox_128(__m128i x) {
    const __m128i low = _mm_set1_epi8(0x0F);
    __m128i hi = _mm_and_si128(_mm_srli_epi32(x, 4), low);
    __m128i lo = _mm_and_si128(x, low);
    x = _mm_xor_si128(_mm_shuffle_epi8(_mm_set_epi8(PRE_LO), lo),
                      _mm_shuffle_epi8(_mm_set_epi8(PRE_HI), hi));
    x = _mm_aesenclast_si128(x, _mm_setzero_si128());
    x = _mm_shuffle_epi8(x, _mm_set_epi8(INV_SHIFT_ROWS));
    hi = _mm_and_si128(_mm_srli_epi32(x, 4), low);
    lo = _mm_and_si128(x, low);
    return _mm_xor_si128(_mm_shuffle_epi8(_mm_set_epi8(POST_LO), lo),
                         _mm_shuffle_epi8(_mm_set_epi8(POST_HI), hi));
}

/* 256-bit linear layer; shared by the two AVX2 tiers through a macro for the target. */
#define SM4_L_256_BODY                                                                             \
    const __m256i r8 = _mm256_broadcastsi128_si256(_mm_set_epi8(ROL8_SHUFFLE));                    \
    const __m256i r16 = _mm256_broadcastsi128_si256(_mm_set_epi8(ROL16_SHUFFLE));                  \
    const __m256i r24 = _mm256_broadcastsi128_si256(_mm_set_epi8(ROL24_SHUFFLE));                  \
    __m256i y = _mm256_xor_si256(_mm256_xor_si256(x, _mm256_shuffle_epi8(x, r8)),                  \
                                 _mm256_shuffle_epi8(x, r16));                                     \
    __m256i z = _mm256_or_si256(_mm256_slli_epi32(y, 2), _mm256_srli_epi32(y, 30));                \
    return _mm256_xor_si256(_mm256_xor_si256(x, _mm256_shuffle_epi8(x, r24)), z);

TARGET_GFNI static inline __m256i sm4_gfni_tau_256(__m256i x) {
    x = _mm256_gf2p8affine_epi64_epi8(x, _mm256_set1_epi64x(GFNI_PRE), GFNI_PRE_C);
    x = _mm256_gf2p8affineinv_epi64_epi8(x, _mm256_set1_epi64x(GFNI_POST), GFNI_POST_C);
    {
        SM4_L_256_BODY
    }
}

TARGET_AESNI256 static inline __m256i sm4_aesni_tau_256(__m256i x) {
    const __m256i low = _mm256_set1_epi8(0x0F);
    const __m256i pre_lo = _mm256_broadcastsi128_si256(_mm_set_epi8(PRE_LO));
    const __m256i pre_hi = _mm256_broadcastsi128_si256(_mm_set_epi8(PRE_HI));
    const __m256i post_lo = _mm256_broadcastsi128_si256(_mm_set_epi8(POST_LO));
    const __m256i post_hi = _mm256_broadcastsi128_si256(_mm_set_epi8(POST_HI));
    const __m256i inv_sr = _mm256_broadcastsi128_si256(_mm_set_epi8(INV_SHIFT_ROWS));
    __m256i hi = _mm256_and_si256(_mm256_srli_epi32(x, 4), low);
    __m256i lo = _mm256_and_si256(x, low);
    __m128i a, b;
    x = _mm256_xor_si256(_mm256_shuffle_epi8(pre_lo, lo), _mm256_shuffle_epi8(pre_hi, hi));
    /* no VAES assumed: run aesenclast on each half */
    a = _mm_aesenclast_si128(_mm256_castsi256_si128(x), _mm_setzero_si128());
    b = _mm_aesenclast_si128(_mm256_extracti128_si256(x, 1), _mm_setzero_si128());
    x = _mm256_inserti128_si256(_mm256_castsi128_si256(a), b, 1);
    x = _mm256_shuffle_epi8(x, inv_sr);
    hi = _mm256_and_si256(_mm256_srli_epi32(x, 4), low);
    lo = _mm256_and_si256(x, low);
    x = _mm256_xor_si256(_mm256_shuffle_epi8(post_lo, lo), _mm256_shuffle_epi8(post_hi, hi));
    {
        SM4_L_256_BODY
    }
}

/* One round over all lanes: A ^= tau(B ^ C ^ D ^ rk). */
#define SM4_ROUND_128(TAU, A, B, C, D, RK)                                                         \
    A = _mm_xor_si128(                                                                             \
        A, TAU(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(B, C), D), _mm_set1_epi32((int)(RK)))))
#define SM4_ROUND_256(TAU, A, B, C, D, RK)                                                         \
    A = _mm256_xor_si256(A, TAU(_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(B, C), D),      \
                                                 _mm256_set1_epi32((int)(RK)))))

/* ---- 8 lanes ---- */

/* Loads 8 blocks into 4 registers of 8 words each, encrypts, stores 8 blocks. */
#define SM4_CRYPT8_BODY(TAU)                                                                       \
    const __m256i bswap = _mm256_broadcastsi128_si256(_mm_set_epi8(BSWAP32_SHUFFLE));              \
    __m256i r0 =                                                                                   \
        _mm256_shuffle_epi8(_mm256_loadu_si256((const __m256i *)(const void *)in), bswap);         \
    __m256i r1 =                                                                                   \
        _mm256_shuffle_epi8(_mm256_loadu_si256((const __m256i *)(const void *)(in + 32)), bswap);  \
    __m256i r2 =                                                                                   \
        _mm256_shuffle_epi8(_mm256_loadu_si256((const __m256i *)(const void *)(in + 64)), bswap);  \
    __m256i r3 =                                                                                   \
        _mm256_shuffle_epi8(_mm256_loadu_si256((const __m256i *)(const void *)(in + 96)), bswap);  \
    __m256i t0 = _mm256_unpacklo_epi32(r0, r1), t1 = _mm256_unpackhi_epi32(r0, r1);                \
    __m256i t2 = _mm256_unpacklo_epi32(r2, r3), t3 = _mm256_unpackhi_epi32(r2, r3);                \
    __m256i a = _mm256_unpacklo_epi64(t0, t2), b = _mm256_unpackhi_epi64(t0, t2);                  \
    __m256i c = _mm256_unpacklo_epi64(t1, t3), d = _mm256_unpackhi_epi64(t1, t3);                  \
    int i;                                                                                         \
    for (i = 0; i < 32; i += 4) {                                                                  \
        SM4_ROUND_256(TAU, a, b, c, d, rk[i]);                                                     \
        SM4_ROUND_256(TAU, b, c, d, a, rk[i + 1]);                                                 \
        SM4_ROUND_256(TAU, c, d, a, b, rk[i + 2]);                                                 \
        SM4_ROUND_256(TAU, d, a, b, c, rk[i + 3]);                                                 \
    }                                                                                              \
    /* final reversal, then undo the transpose */                                                  \
    t0 = _mm256_unpacklo_epi32(d, c);                                                              \
    t1 = _mm256_unpackhi_epi32(d, c);                                                              \
    t2 = _mm256_unpacklo_epi32(b, a);                                                              \
    t3 = _mm256_unpackhi_epi32(b, a);                                                              \
    r0 = _mm256_shuffle_epi8(_mm256_unpacklo_epi64(t0, t2), bswap);                                \
    r1 = _mm256_shuffle_epi8(_mm256_unpackhi_epi64(t0, t2), bswap);                                \
    r2 = _mm256_shuffle_epi8(_mm256_unpacklo_epi64(t1, t3), bswap);                                \
    r3 = _mm256_shuffle_epi8(_mm256_unpackhi_epi64(t1, t3), bswap);                                \
    _mm256_storeu_si256((__m256i *)(void *)out, r0);                                               \
    _mm256_storeu_si256((__m256i *)(void *)(out + 32), r1);                                        \
    _mm256_storeu_si256((__m256i *)(void *)(out + 64), r2);                                        \
    _mm256_storeu_si256((__m256i *)(void *)(out + 96), r3);

TARGET_GFNI static void sm4_gfni_blocks(const uint32_t rk[32], const uint8_t *in,
                                        uint8_t *out){SM4_CRYPT8_BODY(sm4_gfni_tau_256)}

TARGET_AESNI256 static void sm4_aesni256_blocks(const uint32_t rk[32], const uint8_t *in,
                                                uint8_t *out){SM4_CRYPT8_BODY(sm4_aesni_tau_256)}

/* ---- 4 lanes, SSSE3 + AES-NI ---- */

TARGET_AESNI128 static inline __m128i sm4_aesni_tau_128(__m128i x) {
    x = sm4_aesni_sbox_128(x);
    {
        SM4_L_128_BODY
    }
}

TARGET_GFNI static inline __m128i sm4_gfni_tau_128(__m128i x) {
    x = _mm_gf2p8affine_epi64_epi8(x, _mm_set1_epi64x(GFNI_PRE), GFNI_PRE_C);
    x = _mm_gf2p8affineinv_epi64_epi8(x, _mm_set1_epi64x(GFNI_POST), GFNI_POST_C);
    {
        SM4_L_128_BODY
    }
}

TARGET_AESNI128 static void sm4_aesni128_blocks(const uint32_t rk[32], const uint8_t *in,
                                                uint8_t *out) {
    const __m128i bswap = _mm_set_epi8(BSWAP32_SHUFFLE);
    __m128i r0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(const void *)in), bswap);
    __m128i r1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(const void *)(in + 16)), bswap);
    __m128i r2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(const void *)(in + 32)), bswap);
    __m128i r3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(const void *)(in + 48)), bswap);
    __m128i t0 = _mm_unpacklo_epi32(r0, r1), t1 = _mm_unpackhi_epi32(r0, r1);
    __m128i t2 = _mm_unpacklo_epi32(r2, r3), t3 = _mm_unpackhi_epi32(r2, r3);
    __m128i a = _mm_unpacklo_epi64(t0, t2), b = _mm_unpackhi_epi64(t0, t2);
    __m128i c = _mm_unpacklo_epi64(t1, t3), d = _mm_unpackhi_epi64(t1, t3);
    int i;
    for (i = 0; i < 32; i += 4) {
        SM4_ROUND_128(sm4_aesni_tau_128, a, b, c, d, rk[i]);
        SM4_ROUND_128(sm4_aesni_tau_128, b, c, d, a, rk[i + 1]);
        SM4_ROUND_128(sm4_aesni_tau_128, c, d, a, b, rk[i + 2]);
        SM4_ROUND_128(sm4_aesni_tau_128, d, a, b, c, rk[i + 3]);
    }
    t0 = _mm_unpacklo_epi32(d, c);
    t1 = _mm_unpackhi_epi32(d, c);
    t2 = _mm_unpacklo_epi32(b, a);
    t3 = _mm_unpackhi_epi32(b, a);
    _mm_storeu_si128((__m128i *)(void *)out, _mm_shuffle_epi8(_mm_unpacklo_epi64(t0, t2), bswap));
    _mm_storeu_si128((__m128i *)(void *)(out + 16),
                     _mm_shuffle_epi8(_mm_unpackhi_epi64(t0, t2), bswap));
    _mm_storeu_si128((__m128i *)(void *)(out + 32),
                     _mm_shuffle_epi8(_mm_unpacklo_epi64(t1, t3), bswap));
    _mm_storeu_si128((__m128i *)(void *)(out + 48),
                     _mm_shuffle_epi8(_mm_unpackhi_epi64(t1, t3), bswap));
}

/* ---- one lane, for serial CBC encryption ---- */

#define SM4_CBC_ENCRYPT_BODY(TAU)                                                                  \
    __m128i a = _mm_cvtsi32_si128((int)iv[0]), b = _mm_cvtsi32_si128((int)iv[1]);                  \
    __m128i c = _mm_cvtsi32_si128((int)iv[2]), d = _mm_cvtsi32_si128((int)iv[3]);                  \
    uint8_t ct[16];                                                                                \
    for (; blocks > 0; blocks--, in += 16, hex += 32) {                                            \
        __m128i x0, x1, x2, x3;                                                                    \
        int i;                                                                                     \
        x0 = _mm_xor_si128(a, _mm_cvtsi32_si128((int)smx_load_be32(in)));                          \
        x1 = _mm_xor_si128(b, _mm_cvtsi32_si128((int)smx_load_be32(in + 4)));                      \
        x2 = _mm_xor_si128(c, _mm_cvtsi32_si128((int)smx_load_be32(in + 8)));                      \
        x3 = _mm_xor_si128(d, _mm_cvtsi32_si128((int)smx_load_be32(in + 12)));                     \
        for (i = 0; i < 32; i += 4) {                                                              \
            SM4_ROUND_128(TAU, x0, x1, x2, x3, rk[i]);                                             \
            SM4_ROUND_128(TAU, x1, x2, x3, x0, rk[i + 1]);                                         \
            SM4_ROUND_128(TAU, x2, x3, x0, x1, rk[i + 2]);                                         \
            SM4_ROUND_128(TAU, x3, x0, x1, x2, rk[i + 3]);                                         \
        }                                                                                          \
        a = x3;                                                                                    \
        b = x2;                                                                                    \
        c = x1;                                                                                    \
        d = x0;                                                                                    \
        smx_store_be32(ct, (uint32_t)_mm_cvtsi128_si32(a));                                        \
        smx_store_be32(ct + 4, (uint32_t)_mm_cvtsi128_si32(b));                                    \
        smx_store_be32(ct + 8, (uint32_t)_mm_cvtsi128_si32(c));                                    \
        smx_store_be32(ct + 12, (uint32_t)_mm_cvtsi128_si32(d));                                   \
        smx_hex_encode(ct, 16, hex, 'a');                                                          \
    }                                                                                              \
    iv[0] = (uint32_t)_mm_cvtsi128_si32(a);                                                        \
    iv[1] = (uint32_t)_mm_cvtsi128_si32(b);                                                        \
    iv[2] = (uint32_t)_mm_cvtsi128_si32(c);                                                        \
    iv[3] = (uint32_t)_mm_cvtsi128_si32(d);

TARGET_GFNI static void sm4_gfni_cbc_encrypt(const uint32_t rk[32], uint32_t iv[4],
                                             const uint8_t *in, size_t blocks,
                                             char *hex){SM4_CBC_ENCRYPT_BODY(sm4_gfni_tau_128)}

TARGET_AESNI128 static void sm4_aesni_cbc_encrypt(const uint32_t rk[32], uint32_t iv[4],
                                                  const uint8_t *in, size_t blocks, char *hex) {
    SM4_CBC_ENCRYPT_BODY(sm4_aesni_tau_128)
}

#endif /* SMX_SM4_X86 */

/* ---- dispatch ---- */

typedef void (*Sm4BlocksFn)(const uint32_t rk[32], const uint8_t *in, uint8_t *out);
typedef void (*Sm4CbcEncryptFn)(const uint32_t rk[32], uint32_t iv[4], const uint8_t *in,
                                size_t blocks, char *hex);

#define SM4_MAX_LANES 8

/* Written only before main() runs, so it needs no synchronization. */
static Sm4BlocksFn sm4_blocks = sm4_scalar_blocks;
static Sm4CbcEncryptFn sm4_cbc_encrypt_blocks = sm4_scalar_cbc_encrypt;
static size_t sm4_lanes = 1;

#ifdef SMX_SM4_X86
__attribute__((constructor)) static void sm4_detect_cpu(void) {
    unsigned eax, ebx, ecx, edx;
    int ssse3, aes, avx2 = 0, gfni = 0;

    if (__get_cpuid_max(0, NULL) < 1) {
        return;
    }
    __cpuid(1, eax, ebx, ecx, edx);
    ssse3 = (ecx >> 9) & 1;
    aes = (ecx >> 25) & 1;
    if (((ecx >> 27) & 1) != 0 && ((ecx >> 28) & 1) != 0 && __get_cpuid_max(0, NULL) >= 7) {
        /* OSXSAVE and AVX: ask the OS whether it saves the YMM state */
        unsigned xcr0, xcr0_high;
        __asm__ volatile(".byte 0x0f, 0x01, 0xd0" : "=a"(xcr0), "=d"(xcr0_high) : "c"(0));
        if ((xcr0 & 6) == 6) {
            __cpuid_count(7, 0, eax, ebx, ecx, edx);
            avx2 = (ebx >> 5) & 1;
            gfni = (ecx >> 8) & 1;
        }
    }
    (void)ssse3;
    (void)aes;
    (void)avx2;
    (void)gfni;
#if SMX_SM4_MAX_TIER >= 3
    if (avx2 && gfni) {
        sm4_blocks = sm4_gfni_blocks;
        sm4_cbc_encrypt_blocks = sm4_gfni_cbc_encrypt;
        sm4_lanes = 8;
        return;
    }
#endif
#if SMX_SM4_MAX_TIER >= 2
    if (avx2 && aes && ssse3) {
        sm4_blocks = sm4_aesni256_blocks;
        sm4_cbc_encrypt_blocks = sm4_aesni_cbc_encrypt;
        sm4_lanes = 8;
        return;
    }
#endif
#if SMX_SM4_MAX_TIER >= 1
    if (aes && ssse3) {
        sm4_blocks = sm4_aesni128_blocks;
        sm4_cbc_encrypt_blocks = sm4_aesni_cbc_encrypt;
        sm4_lanes = 4;
        return;
    }
#endif
}
#endif

/* ---- key schedule ---- */

/* prepare key: if not 16 bytes, hash with SM3 and take first 16 hex chars */
static void sm4_prepare_key(const uint8_t *input, size_t len, uint8_t out[16]) {
    SM3 h;
    if (len == 16) {
        memcpy(out, input, 16);
        return;
    }
    sm3_init(&h);
    sm3_update(&h, input, len);
    sm3_finish(&h);
    /* take first 16 characters of uppercase hex as key bytes */
    memcpy(out, h.hash_hex, 16);
}

/*
 * Uses the plain S-box on every platform. The expansion runs once per key, so a
 * vector path would add code without measurable benefit; the secret-indexed
 * access caveat of the baseline applies here unchanged.
 */
static inline uint32_t sm4_tau(uint32_t a) {
    return ((uint32_t)sm4_sbox[a >> 24] << 24) | ((uint32_t)sm4_sbox[(a >> 16) & 0xFF] << 16) |
           ((uint32_t)sm4_sbox[(a >> 8) & 0xFF] << 8) | (uint32_t)sm4_sbox[a & 0xFF];
}

static void sm4_init_key(SM4 *ctx, const uint8_t key[16], const uint8_t iv[16]) {
    uint32_t k0 = smx_load_be32(key) ^ sm4_fk[0];
    uint32_t k1 = smx_load_be32(key + 4) ^ sm4_fk[1];
    uint32_t k2 = smx_load_be32(key + 8) ^ sm4_fk[2];
    uint32_t k3 = smx_load_be32(key + 12) ^ sm4_fk[3];
    int i;

    for (i = 0; i < 32; i++) {
        uint32_t b = sm4_tau(k1 ^ k2 ^ k3 ^ sm4_ck[i]);
        uint32_t next = k0 ^ b ^ ROL32(b, 13) ^ ROL32(b, 23);
        ctx->rk[i] = next;
        k0 = k1;
        k1 = k2;
        k2 = k3;
        k3 = next;
    }
    memcpy(ctx->iv, iv, 16);
}

/* ---- public API ---- */

void sm4_init(SM4 *ctx) {
    memset(ctx, 0, sizeof(SM4));
}

void sm4_set_key(SM4 *ctx, const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len) {
    uint8_t key_bytes[16], iv_bytes[16];
    sm4_prepare_key(key, key_len, key_bytes);
    sm4_prepare_key(iv, iv_len, iv_bytes);
    sm4_init_key(ctx, key_bytes, iv_bytes);
}

char *sm4_encrypt(SM4 *ctx, const char *plaintext) {
    size_t input_len = strlen(plaintext);
    size_t full_blocks = input_len / 16;
    size_t tail = input_len - full_blocks * 16;
    size_t total = (full_blocks + 1) * 16;
    uint8_t last[16];
    uint32_t iv[4];
    char *hex = (char *)malloc(total * 2 + 1);
    int i;

    if (hex == NULL) {
        return NULL;
    }
    for (i = 0; i < 4; i++) {
        iv[i] = smx_load_be32(ctx->iv + i * 4);
    }
    /* whole blocks come straight from the caller's string; only the last is padded */
    sm4_cbc_encrypt_blocks(ctx->rk, iv, (const uint8_t *)plaintext, full_blocks, hex);
    memset(last, (int)(16 - tail), 16);
    if (tail > 0) {
        memcpy(last, plaintext + full_blocks * 16, tail);
    }
    sm4_cbc_encrypt_blocks(ctx->rk, iv, last, 1, hex + full_blocks * 32);
    hex[total * 2] = '\0';
    return hex;
}

static inline void xor_block(uint8_t *out, const uint8_t *a, const uint8_t *b) {
    uint64_t x[2], y[2];
    memcpy(x, a, 16);
    memcpy(y, b, 16);
    x[0] ^= y[0];
    x[1] ^= y[1];
    memcpy(out, x, 16);
}

/*
 * CBC decryption in place. Working from the last block backwards means every
 * block's predecessor is still ciphertext when it is needed, so no copies of the
 * chaining value are kept.
 */
static void sm4_cbc_decrypt_in_place(const SM4 *ctx, uint8_t *buf, size_t blocks) {
    uint32_t rk[32];
    uint8_t tmp[SM4_MAX_LANES * 16];
    size_t lanes = sm4_lanes;
    int i;

    for (i = 0; i < 32; i++) {
        rk[i] = ctx->rk[31 - i];
    }
    while (blocks > 0) {
        size_t count = blocks < lanes ? blocks : lanes;
        size_t start = blocks - count;
        size_t j;
        if (count == lanes) {
            sm4_blocks(rk, buf + start * 16, tmp);
        } else {
            uint8_t partial[SM4_MAX_LANES * 16];
            memset(partial, 0, sizeof(partial));
            memcpy(partial, buf + start * 16, count * 16);
            sm4_blocks(rk, partial, tmp);
        }
        for (j = count; j > 0; j--) {
            size_t index = start + j - 1;
            const uint8_t *prev = index == 0 ? ctx->iv : buf + (index - 1) * 16;
            xor_block(buf + index * 16, tmp + (j - 1) * 16, prev);
        }
        blocks = start;
    }
}

/* Reads the whole padding, so where it first goes wrong does not show in the timing. */
static int pkcs7_unpad(const uint8_t *input, size_t len, size_t *out_len) {
    unsigned pad_len;
    unsigned diff = 0;
    size_t i;
    if (len == 0) {
        *out_len = 0;
        return 0;
    }
    pad_len = input[len - 1];
    if (pad_len == 0 || pad_len > 16 || pad_len > len) {
        return -1;
    }
    for (i = len - pad_len; i < len; i++) {
        diff |= input[i] ^ pad_len;
    }
    if (diff != 0) {
        return -1;
    }
    *out_len = len - pad_len;
    return 0;
}

char *sm4_decrypt(SM4 *ctx, const char *ciphertext_hex) {
    size_t byte_len = strlen(ciphertext_hex) / 2;
    size_t unpadded_len;
    uint8_t *buf;

    if (byte_len % 16 != 0) {
        return NULL;
    }
    buf = (uint8_t *)malloc(byte_len + 1);
    if (buf == NULL) {
        return NULL;
    }
    /* a 0x prefix makes the decode one byte short */
    if (byte_len > 0) {
        buf[byte_len - 1] = 0;
    }
    hex_to_bytes(ciphertext_hex, buf, byte_len);

    sm4_cbc_decrypt_in_place(ctx, buf, byte_len / 16);

    if (pkcs7_unpad(buf, byte_len, &unpadded_len) != 0) {
        free(buf);
        return NULL;
    }
    buf[unpadded_len] = '\0';
    return (char *)buf;
}
