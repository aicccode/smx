#include "smx_internal.h"
#include <stdlib.h>
#include <string.h>

/*
 * SM4 in CBC mode with PKCS7 padding.
 *
 * Block implementations, picked once at load time from what the CPU reports:
 *   tier 3  GFNI + AVX2      8 blocks at a time
 *   tier 2  AES-NI + AVX2    8 blocks at a time
 *   tier 1  AES-NI + SSSE3   4 blocks at a time; on arm64, NEON + AES instructions
 *   tier 0  portable C       1 block at a time, Boolean-circuit S-box
 *
 * No tier has a table indexed by secret data and none branches on secret data, the
 * key schedule included. The only lookups are vector shuffles and fixed tables of
 * affine constants, which are constant time on the instructions used here.
 *
 * CBC decryption is parallel and uses the full width. CBC encryption is inherently
 * serial and runs one block through the vector S-box.
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

/* Compile-time only: arm64 builds without these flags fall back to the circuit. */
#if defined(__aarch64__) && defined(__ARM_NEON) && defined(__ARM_FEATURE_AES) &&                   \
    defined(__LITTLE_ENDIAN__) && !defined(SMX_NO_SIMD) && SMX_SM4_MAX_TIER >= 1
#define SMX_SM4_NEON 1
#include <arm_neon.h>
#endif

#include "sm4_sbox_circuit.inc"

static const uint32_t sm4_fk[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

static const uint32_t sm4_ck[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/* ---- portable path ---- */

static inline uint32_t sm4_scalar_t(uint32_t x) {
    uint32_t b = sm4_sbox_circuit(x);
    return b ^ ROL32(b, 2) ^ ROL32(b, 10) ^ ROL32(b, 18) ^ ROL32(b, 24);
}

static inline void sm4_scalar_rounds(const uint32_t rk[32], uint32_t x[4]) {
    uint32_t a = x[0], b = x[1], c = x[2], d = x[3], t;
    int i;
    for (i = 0; i < 32; i += 4) {
        t = b ^ c ^ d ^ rk[i];
        a ^= sm4_scalar_t(t);
        t = c ^ d ^ a ^ rk[i + 1];
        b ^= sm4_scalar_t(t);
        t = d ^ a ^ b ^ rk[i + 2];
        c ^= sm4_scalar_t(t);
        t = a ^ b ^ c ^ rk[i + 3];
        d ^= sm4_scalar_t(t);
    }
    /* the final reversal */
    x[0] = d;
    x[1] = c;
    x[2] = b;
    x[3] = a;
}

SMX_MAYBE_UNUSED static void sm4_scalar_blocks(const uint32_t rk[32], const uint8_t *in,
                                               uint8_t *out) {
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

SMX_MAYBE_UNUSED static void sm4_scalar_cbc_encrypt(const uint32_t rk[32], uint32_t iv[4],
                                                    const uint8_t *in, size_t blocks, char *hex) {
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
    smx_wipe(x, sizeof(x));
    smx_wipe(ct, sizeof(ct));
}

SMX_MAYBE_UNUSED static uint32_t sm4_scalar_sbox_word(uint32_t x) {
    return sm4_sbox_circuit(x);
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

TARGET_AESNI128
    static void sm4_aesni_cbc_encrypt(const uint32_t rk[32], uint32_t iv[4], const uint8_t *in,
                                      size_t blocks,
                                      char *hex){SM4_CBC_ENCRYPT_BODY(sm4_aesni_tau_128)}

/* S-box on one word, for the key schedule. */
TARGET_GFNI static uint32_t sm4_gfni_sbox_word(uint32_t w) {
    __m128i x = _mm_cvtsi32_si128((int)w);
    x = _mm_gf2p8affine_epi64_epi8(x, _mm_set1_epi64x(GFNI_PRE), GFNI_PRE_C);
    x = _mm_gf2p8affineinv_epi64_epi8(x, _mm_set1_epi64x(GFNI_POST), GFNI_POST_C);
    return (uint32_t)_mm_cvtsi128_si32(x);
}

TARGET_AESNI128 static uint32_t sm4_aesni_sbox_word(uint32_t w) {
    return (uint32_t)_mm_cvtsi128_si32(sm4_aesni_sbox_128(_mm_cvtsi32_si128((int)w)));
}

#endif /* SMX_SM4_X86 */

/* ---- arm64 path: the AES S-box with SM4's affine maps around it ---- */

#ifdef SMX_SM4_NEON

static const uint8_t SM4_NEON_PRE_LO[16] = {0x01, 0x07, 0x72, 0x74, 0xE4, 0xE2, 0x97, 0x91,
                                            0x57, 0x51, 0x24, 0x22, 0xB2, 0xB4, 0xC1, 0xC7};
static const uint8_t SM4_NEON_PRE_HI[16] = {0x00, 0xA2, 0x49, 0xEB, 0x09, 0xAB, 0x40, 0xE2,
                                            0x12, 0xB0, 0x5B, 0xF9, 0x1B, 0xB9, 0x52, 0xF0};
static const uint8_t SM4_NEON_POST_LO[16] = {0x34, 0x08, 0x9D, 0xA1, 0xCE, 0xF2, 0x67, 0x5B,
                                             0x82, 0xBE, 0x2B, 0x17, 0x78, 0x44, 0xD1, 0xED};
static const uint8_t SM4_NEON_POST_HI[16] = {0x00, 0xDC, 0xAF, 0x73, 0xDD, 0x01, 0x72, 0xAE,
                                             0xBF, 0x63, 0x10, 0xCC, 0x62, 0xBE, 0xCD, 0x11};
static const uint8_t SM4_NEON_INV_SR[16] = {0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3};
static const uint8_t SM4_NEON_ROL8[16] = {3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14};
static const uint8_t SM4_NEON_ROL24[16] = {1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12};

static inline uint8x16_t sm4_neon_sbox(uint8x16_t x) {
    const uint8x16_t low = vdupq_n_u8(0x0F);
    uint8x16_t t = veorq_u8(vqtbl1q_u8(vld1q_u8(SM4_NEON_PRE_LO), vandq_u8(x, low)),
                            vqtbl1q_u8(vld1q_u8(SM4_NEON_PRE_HI), vshrq_n_u8(x, 4)));
    t = vaeseq_u8(t, vdupq_n_u8(0));
    t = vqtbl1q_u8(t, vld1q_u8(SM4_NEON_INV_SR));
    return veorq_u8(vqtbl1q_u8(vld1q_u8(SM4_NEON_POST_LO), vandq_u8(t, low)),
                    vqtbl1q_u8(vld1q_u8(SM4_NEON_POST_HI), vshrq_n_u8(t, 4)));
}

/* tau followed by L, on 32-bit lanes */
static inline uint32x4_t sm4_neon_t(uint32x4_t in) {
    uint8x16_t b = sm4_neon_sbox(vreinterpretq_u8_u32(in));
    uint8x16_t y = veorq_u8(veorq_u8(b, vqtbl1q_u8(b, vld1q_u8(SM4_NEON_ROL8))),
                            vreinterpretq_u8_u16(vrev32q_u16(vreinterpretq_u16_u8(b))));
    uint32x4_t yw = vreinterpretq_u32_u8(y);
    uint32x4_t z = vsliq_n_u32(vshrq_n_u32(yw, 30), yw, 2);
    return veorq_u32(vreinterpretq_u32_u8(veorq_u8(b, vqtbl1q_u8(b, vld1q_u8(SM4_NEON_ROL24)))), z);
}

#define SM4_NEON_ROUND(A, B, C, D, RK)                                                             \
    A = veorq_u32(A, sm4_neon_t(veorq_u32(veorq_u32(veorq_u32(B, C), D), vdupq_n_u32(RK))))

static void sm4_neon_blocks(const uint32_t rk[32], const uint8_t *in, uint8_t *out) {
    uint32x4x4_t v = vld4q_u32((const uint32_t *)(const void *)in);
    uint32x4_t a = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v.val[0])));
    uint32x4_t b = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v.val[1])));
    uint32x4_t c = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v.val[2])));
    uint32x4_t d = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v.val[3])));
    int i;
    for (i = 0; i < 32; i += 4) {
        SM4_NEON_ROUND(a, b, c, d, rk[i]);
        SM4_NEON_ROUND(b, c, d, a, rk[i + 1]);
        SM4_NEON_ROUND(c, d, a, b, rk[i + 2]);
        SM4_NEON_ROUND(d, a, b, c, rk[i + 3]);
    }
    v.val[0] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(d)));
    v.val[1] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(c)));
    v.val[2] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(b)));
    v.val[3] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(a)));
    vst4q_u32((uint32_t *)(void *)out, v);
}

static void sm4_neon_cbc_encrypt(const uint32_t rk[32], uint32_t iv[4], const uint8_t *in,
                                 size_t blocks, char *hex) {
    uint32x4_t a = vsetq_lane_u32(iv[0], vdupq_n_u32(0), 0);
    uint32x4_t b = vsetq_lane_u32(iv[1], vdupq_n_u32(0), 0);
    uint32x4_t c = vsetq_lane_u32(iv[2], vdupq_n_u32(0), 0);
    uint32x4_t d = vsetq_lane_u32(iv[3], vdupq_n_u32(0), 0);
    uint8_t ct[16];
    for (; blocks > 0; blocks--, in += 16, hex += 32) {
        uint32x4_t x0 = veorq_u32(a, vsetq_lane_u32(smx_load_be32(in), vdupq_n_u32(0), 0));
        uint32x4_t x1 = veorq_u32(b, vsetq_lane_u32(smx_load_be32(in + 4), vdupq_n_u32(0), 0));
        uint32x4_t x2 = veorq_u32(c, vsetq_lane_u32(smx_load_be32(in + 8), vdupq_n_u32(0), 0));
        uint32x4_t x3 = veorq_u32(d, vsetq_lane_u32(smx_load_be32(in + 12), vdupq_n_u32(0), 0));
        int i;
        for (i = 0; i < 32; i += 4) {
            SM4_NEON_ROUND(x0, x1, x2, x3, rk[i]);
            SM4_NEON_ROUND(x1, x2, x3, x0, rk[i + 1]);
            SM4_NEON_ROUND(x2, x3, x0, x1, rk[i + 2]);
            SM4_NEON_ROUND(x3, x0, x1, x2, rk[i + 3]);
        }
        a = x3;
        b = x2;
        c = x1;
        d = x0;
        smx_store_be32(ct, vgetq_lane_u32(a, 0));
        smx_store_be32(ct + 4, vgetq_lane_u32(b, 0));
        smx_store_be32(ct + 8, vgetq_lane_u32(c, 0));
        smx_store_be32(ct + 12, vgetq_lane_u32(d, 0));
        smx_hex_encode(ct, 16, hex, 'a');
    }
    iv[0] = vgetq_lane_u32(a, 0);
    iv[1] = vgetq_lane_u32(b, 0);
    iv[2] = vgetq_lane_u32(c, 0);
    iv[3] = vgetq_lane_u32(d, 0);
    smx_wipe(ct, sizeof(ct));
}

static uint32_t sm4_neon_sbox_word(uint32_t w) {
    uint8x16_t x = vreinterpretq_u8_u32(vsetq_lane_u32(w, vdupq_n_u32(0), 0));
    return vgetq_lane_u32(vreinterpretq_u32_u8(sm4_neon_sbox(x)), 0);
}

#endif /* SMX_SM4_NEON */

/* ---- dispatch ---- */

typedef void (*Sm4BlocksFn)(const uint32_t rk[32], const uint8_t *in, uint8_t *out);
typedef void (*Sm4CbcEncryptFn)(const uint32_t rk[32], uint32_t iv[4], const uint8_t *in,
                                size_t blocks, char *hex);
typedef uint32_t (*Sm4SboxWordFn)(uint32_t w);

#define SM4_MAX_LANES 8

/* Written only before main() runs, so it needs no synchronization. */
#ifdef SMX_SM4_NEON
static const Sm4BlocksFn sm4_blocks = sm4_neon_blocks;
static const Sm4CbcEncryptFn sm4_cbc_encrypt_blocks = sm4_neon_cbc_encrypt;
static const Sm4SboxWordFn sm4_sbox_word = sm4_neon_sbox_word;
static const size_t sm4_lanes = 4;
#else
static Sm4BlocksFn sm4_blocks = sm4_scalar_blocks;
static Sm4CbcEncryptFn sm4_cbc_encrypt_blocks = sm4_scalar_cbc_encrypt;
static Sm4SboxWordFn sm4_sbox_word = sm4_scalar_sbox_word;
static size_t sm4_lanes = 1;
#endif

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
        sm4_sbox_word = sm4_gfni_sbox_word;
        sm4_lanes = 8;
        return;
    }
#endif
#if SMX_SM4_MAX_TIER >= 2
    if (avx2 && aes && ssse3) {
        sm4_blocks = sm4_aesni256_blocks;
        sm4_cbc_encrypt_blocks = sm4_aesni_cbc_encrypt;
        sm4_sbox_word = sm4_aesni_sbox_word;
        sm4_lanes = 8;
        return;
    }
#endif
#if SMX_SM4_MAX_TIER >= 1
    if (aes && ssse3) {
        sm4_blocks = sm4_aesni128_blocks;
        sm4_cbc_encrypt_blocks = sm4_aesni_cbc_encrypt;
        sm4_sbox_word = sm4_aesni_sbox_word;
        sm4_lanes = 4;
        return;
    }
#endif
}
#endif

/* ---- key schedule ---- */

/* Marks a context as holding a valid key; anything else is refused. */
#define SM4_KEY_SET 0x534D3421u

static void sm4_expand_key(SM4 *ctx, const uint8_t key[16]) {
    uint32_t k0 = smx_load_be32(key) ^ sm4_fk[0];
    uint32_t k1 = smx_load_be32(key + 4) ^ sm4_fk[1];
    uint32_t k2 = smx_load_be32(key + 8) ^ sm4_fk[2];
    uint32_t k3 = smx_load_be32(key + 12) ^ sm4_fk[3];
    int i;

    for (i = 0; i < 32; i++) {
        uint32_t b = sm4_sbox_word(k1 ^ k2 ^ k3 ^ sm4_ck[i]);
        uint32_t next = k0 ^ b ^ ROL32(b, 13) ^ ROL32(b, 23);
        ctx->rk[i] = next;
        k0 = k1;
        k1 = k2;
        k2 = k3;
        k3 = next;
    }
    smx_wipe(&k0, sizeof(k0));
    smx_wipe(&k1, sizeof(k1));
    smx_wipe(&k2, sizeof(k2));
    smx_wipe(&k3, sizeof(k3));
}

/* ---- public API ---- */

void sm4_init(SM4 *ctx) {
    if (ctx != NULL) {
        smx_wipe(ctx, sizeof(SM4));
    }
}

void sm4_set_key(SM4 *ctx, const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len) {
    uint8_t key_copy[16], iv_copy[16];
    int valid;
    if (ctx == NULL) {
        return;
    }
    /* key or iv may point into ctx itself, so they are read before it is cleared */
    valid = key != NULL && iv != NULL && key_len == 16 && iv_len == 16;
    if (valid) {
        memmove(key_copy, key, 16);
        memmove(iv_copy, iv, 16);
    }
    smx_wipe(ctx, sizeof(SM4));
    if (!valid) {
        return; /* the context stays unset, and encrypt and decrypt return NULL */
    }
    sm4_expand_key(ctx, key_copy);
    memcpy(ctx->iv, iv_copy, 16);
    ctx->key_state = SM4_KEY_SET;
    smx_wipe(key_copy, sizeof(key_copy));
    smx_wipe(iv_copy, sizeof(iv_copy));
}

char *sm4_encrypt_bytes(SM4 *ctx, const uint8_t *data, size_t input_len) {
    size_t full_blocks, tail, total;
    uint8_t last[16];
    uint32_t iv[4];
    char *hex;
    int i;

    if (ctx == NULL || ctx->key_state != SM4_KEY_SET || (data == NULL && input_len != 0)) {
        return NULL;
    }
    full_blocks = input_len / 16;
    tail = input_len - full_blocks * 16;
    /* 16 bytes of ciphertext become 32 characters, plus the terminator */
    if (full_blocks >= (SIZE_MAX - 1) / 32 - 1) {
        return NULL;
    }
    total = (full_blocks + 1) * 16;
    hex = (char *)malloc(total * 2 + 1);
    if (hex == NULL) {
        return NULL;
    }
    for (i = 0; i < 4; i++) {
        iv[i] = smx_load_be32(ctx->iv + i * 4);
    }
    /* whole blocks come straight from the caller's buffer; only the last is padded */
    if (full_blocks > 0) {
        sm4_cbc_encrypt_blocks(ctx->rk, iv, data, full_blocks, hex);
    }
    memset(last, (int)(16 - tail), 16);
    if (tail > 0) {
        memcpy(last, data + full_blocks * 16, tail);
    }
    sm4_cbc_encrypt_blocks(ctx->rk, iv, last, 1, hex + full_blocks * 32);
    hex[total * 2] = '\0';
    smx_wipe(last, sizeof(last));
    return hex;
}

char *sm4_encrypt(SM4 *ctx, const char *plaintext) {
    if (plaintext == NULL) {
        return NULL;
    }
    return sm4_encrypt_bytes(ctx, (const uint8_t *)plaintext, strlen(plaintext));
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
    uint8_t partial[SM4_MAX_LANES * 16];
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
    smx_wipe(rk, sizeof(rk));
    smx_wipe(tmp, sizeof(tmp));
    smx_wipe(partial, sizeof(partial));
}

/*
 * Constant-flow PKCS#7 check over the whole last block: the same work and the same
 * memory accesses for every padding value, valid or not. Returns an all-ones mask if
 * the padding is valid, and *out_len is then the plaintext length.
 */
static SMX_NOINLINE uint64_t pkcs7_check(const uint8_t *input, size_t len, size_t *out_len) {
    uint64_t pad = input[len - 1];
    /* 1 <= pad <= 16 */
    uint64_t ok = smx_mask_is_zero((pad - 1) >> 4);
    uint64_t diff = 0;
    uint64_t i;
    for (i = 0; i < 16; i++) {
        /* all ones when i < pad, that is, when this byte belongs to the padding */
        uint64_t covered = smx_mask_from_bit((i - pad) >> 63);
        diff |= covered & (input[len - 1 - i] ^ pad);
    }
    *out_len = len - (size_t)pad;
    return ok & smx_mask_is_zero(diff);
}

/*
 * Everything that follows the hex decode, with the same work whether the padding is valid or
 * not: a timing difference here would be a padding oracle even for a caller that hides the
 * error. There is no UTF-8 step in C, since the result is bytes. The buffer is erased with a
 * mask, so a valid result passes through the same writes. Returns the validity mask.
 */
static SMX_NOINLINE uint64_t sm4_decrypt_core(const SM4 *ctx, uint8_t *buf, size_t byte_len,
                                              size_t *plain_len) {
    uint64_t valid;
    size_t i;
    sm4_cbc_decrypt_in_place(ctx, buf, byte_len / 16);
    valid = pkcs7_check(buf, byte_len, plain_len);
    for (i = 0; i < byte_len; i++) {
        buf[i] = (uint8_t)(buf[i] & valid);
    }
    return valid;
}

uint8_t *sm4_decrypt_bytes(SM4 *ctx, const char *ciphertext_hex, size_t *out_len) {
    size_t hex_len, byte_len, plain_len;
    uint8_t *buf;
    uint64_t valid;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (ctx == NULL || ctx->key_state != SM4_KEY_SET || ciphertext_hex == NULL) {
        return NULL;
    }
    hex_len = strlen(ciphertext_hex);
    byte_len = hex_len / 2;
    if ((hex_len & 1) != 0 || byte_len == 0 || byte_len % 16 != 0) {
        return NULL;
    }
    buf = (uint8_t *)malloc(byte_len + 1);
    if (buf == NULL) {
        return NULL;
    }
    if (!smx_hex_decode_lower(ciphertext_hex, byte_len, buf)) {
        free(buf);
        return NULL;
    }

    valid = sm4_decrypt_core(ctx, buf, byte_len, &plain_len);
    SMX_DECLASSIFY(&valid, sizeof(valid));
    if (!valid) {
        free(buf);
        return NULL;
    }
    SMX_DECLASSIFY(&plain_len, sizeof(plain_len));
    buf[plain_len] = '\0';
    if (out_len != NULL) {
        *out_len = plain_len;
    }
    return buf;
}

char *sm4_decrypt(SM4 *ctx, const char *ciphertext_hex) {
    return (char *)sm4_decrypt_bytes(ctx, ciphertext_hex, NULL);
}

/* ---- SM4-ECB for SM9 encryption (declared in smx_internal.h) ---- */

/* ECB over whole blocks with this branch's constant-time block function, sm4_lanes at a time. */
static void sm4_ecb_blocks(const uint32_t rk[32], const uint8_t *in, uint8_t *out, size_t blocks) {
    uint8_t partial[SM4_MAX_LANES * 16];
    uint8_t tmp[SM4_MAX_LANES * 16];
    size_t lanes = sm4_lanes;
    while (blocks > 0) {
        size_t count = blocks < lanes ? blocks : lanes;
        if (count == lanes) {
            sm4_blocks(rk, in, out);
        } else {
            memset(partial, 0, sizeof(partial));
            memcpy(partial, in, count * 16);
            sm4_blocks(rk, partial, tmp);
            memcpy(out, tmp, count * 16);
        }
        in += count * 16;
        out += count * 16;
        blocks -= count;
    }
    smx_wipe(partial, sizeof(partial));
    smx_wipe(tmp, sizeof(tmp));
}

void smx_sm4_ecb_encrypt(const uint8_t key[16], const uint8_t *in, uint8_t *out, size_t blocks) {
    SM4 ctx;
    sm4_expand_key(&ctx, key);
    sm4_ecb_blocks(ctx.rk, in, out, blocks);
    smx_wipe(&ctx, sizeof(ctx));
}

uint64_t smx_sm4_ecb_decrypt_pkcs7(const uint8_t key[16], uint8_t *buf, size_t len,
                                   size_t *plain_len) {
    SM4 ctx;
    uint32_t rk[32];
    size_t i;
    sm4_expand_key(&ctx, key);
    for (i = 0; i < 32; i++) {
        rk[i] = ctx.rk[31 - i];
    }
    sm4_ecb_blocks(rk, buf, buf, len / 16);
    smx_wipe(&ctx, sizeof(ctx));
    smx_wipe(rk, sizeof(rk));
    return pkcs7_check(buf, len, plain_len);
}
