#include "smx_internal.h"
#include <stdlib.h>
#include <string.h>

/*
 * SM4 in CBC mode with PKCS7 padding.
 *
 * This is the high-performance variant: the key schedule, CBC encryption, single blocks
 * and short CBC decryptions use lookup tables indexed by secret data (four 1 KiB "T-tables"
 * that fold the S-box into the linear layer, and four more for the key schedule), the
 * classic approach of OpenSSL and BouncyCastle. Their timing can leak key and data bits
 * through the cache, so this SM4 is NOT cache-timing resistant. The `security` branch of
 * this repository has the constant-time SM4 (Boolean-circuit S-box, no secret-indexed
 * table anywhere).
 *
 * Longer CBC decryptions, which are parallel, run many blocks at once where the CPU has
 * the instructions, picked once at load time:
 *   tier 3  GFNI + AVX2           8 blocks at a time
 *   tier 2  AES-NI + AVX2         8 blocks at a time
 *   tier 1  arm64 NEON + AES     32 blocks at a time (x86 has no tier 1: AES-NI with only
 *                                 128-bit vectors measured slower than the tables)
 *   tier 0  tables, four blocks interleaved
 * The blocks left over after the whole batches go through the tables when that is cheaper
 * than a padded batch. A single block always does.
 *
 * Define SMX_NO_SIMD to build only tier 0, or SMX_SM4_MAX_TIER to cap the tier;
 * `make check-fallbacks` runs the tests against every tier.
 */

#ifndef SMX_SM4_MAX_TIER
#define SMX_SM4_MAX_TIER 3
#endif

#if defined(__x86_64__) && !defined(SMX_NO_SIMD) && SMX_SM4_MAX_TIER >= 2 &&                       \
    (defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 8))
#define SMX_SM4_X86 1
#include <cpuid.h>
#include <immintrin.h>
#endif

/* Compile-time only: arm64 builds without these flags use the tables alone. */
#if defined(__aarch64__) && defined(__ARM_NEON) && defined(__ARM_FEATURE_AES) &&                   \
    defined(__LITTLE_ENDIAN__) && !defined(SMX_NO_SIMD) && SMX_SM4_MAX_TIER >= 1
#define SMX_SM4_NEON 1
#include <arm_neon.h>
#endif

static const uint32_t sm4_fk[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

static const uint32_t sm4_ck[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/*
 * Erases secrets. With GCC and clang this is memset, kept by an empty asm that may read
 * the memory, which is as reliable as smx_wipe and much faster than its byte loop.
 */
static inline void sm4_wipe(void *p, size_t n) {
#if defined(__GNUC__)
    memset(p, 0, n);
    __asm__ __volatile__("" : : "r"(p) : "memory");
#else
    smx_wipe(p, n);
#endif
}

/* ---- tables ---- */

/* The S-box of GB/T 32907, as a list so that every table below is built from it. */
/* clang-format off */
#define SM4_SBOX_LIST(X)                                            \
    X(0xd6) X(0x90) X(0xe9) X(0xfe) X(0xcc) X(0xe1) X(0x3d) X(0xb7) \
    X(0x16) X(0xb6) X(0x14) X(0xc2) X(0x28) X(0xfb) X(0x2c) X(0x05) \
    X(0x2b) X(0x67) X(0x9a) X(0x76) X(0x2a) X(0xbe) X(0x04) X(0xc3) \
    X(0xaa) X(0x44) X(0x13) X(0x26) X(0x49) X(0x86) X(0x06) X(0x99) \
    X(0x9c) X(0x42) X(0x50) X(0xf4) X(0x91) X(0xef) X(0x98) X(0x7a) \
    X(0x33) X(0x54) X(0x0b) X(0x43) X(0xed) X(0xcf) X(0xac) X(0x62) \
    X(0xe4) X(0xb3) X(0x1c) X(0xa9) X(0xc9) X(0x08) X(0xe8) X(0x95) \
    X(0x80) X(0xdf) X(0x94) X(0xfa) X(0x75) X(0x8f) X(0x3f) X(0xa6) \
    X(0x47) X(0x07) X(0xa7) X(0xfc) X(0xf3) X(0x73) X(0x17) X(0xba) \
    X(0x83) X(0x59) X(0x3c) X(0x19) X(0xe6) X(0x85) X(0x4f) X(0xa8) \
    X(0x68) X(0x6b) X(0x81) X(0xb2) X(0x71) X(0x64) X(0xda) X(0x8b) \
    X(0xf8) X(0xeb) X(0x0f) X(0x4b) X(0x70) X(0x56) X(0x9d) X(0x35) \
    X(0x1e) X(0x24) X(0x0e) X(0x5e) X(0x63) X(0x58) X(0xd1) X(0xa2) \
    X(0x25) X(0x22) X(0x7c) X(0x3b) X(0x01) X(0x21) X(0x78) X(0x87) \
    X(0xd4) X(0x00) X(0x46) X(0x57) X(0x9f) X(0xd3) X(0x27) X(0x52) \
    X(0x4c) X(0x36) X(0x02) X(0xe7) X(0xa0) X(0xc4) X(0xc8) X(0x9e) \
    X(0xea) X(0xbf) X(0x8a) X(0xd2) X(0x40) X(0xc7) X(0x38) X(0xb5) \
    X(0xa3) X(0xf7) X(0xf2) X(0xce) X(0xf9) X(0x61) X(0x15) X(0xa1) \
    X(0xe0) X(0xae) X(0x5d) X(0xa4) X(0x9b) X(0x34) X(0x1a) X(0x55) \
    X(0xad) X(0x93) X(0x32) X(0x30) X(0xf5) X(0x8c) X(0xb1) X(0xe3) \
    X(0x1d) X(0xf6) X(0xe2) X(0x2e) X(0x82) X(0x66) X(0xca) X(0x60) \
    X(0xc0) X(0x29) X(0x23) X(0xab) X(0x0d) X(0x53) X(0x4e) X(0x6f) \
    X(0xd5) X(0xdb) X(0x37) X(0x45) X(0xde) X(0xfd) X(0x8e) X(0x2f) \
    X(0x03) X(0xff) X(0x6a) X(0x72) X(0x6d) X(0x6c) X(0x5b) X(0x51) \
    X(0x8d) X(0x1b) X(0xaf) X(0x92) X(0xbb) X(0xdd) X(0xbc) X(0x7f) \
    X(0x11) X(0xd9) X(0x5c) X(0x41) X(0x1f) X(0x10) X(0x5a) X(0xd8) \
    X(0x0a) X(0xc1) X(0x31) X(0x88) X(0xa5) X(0xcd) X(0x7b) X(0xbd) \
    X(0x2d) X(0x74) X(0xd0) X(0x12) X(0xb8) X(0xe5) X(0xb4) X(0xb0) \
    X(0x89) X(0x69) X(0x97) X(0x4a) X(0x0c) X(0x96) X(0x77) X(0x7e) \
    X(0x65) X(0xb9) X(0xf1) X(0x09) X(0xc5) X(0x6e) X(0xc6) X(0x84) \
    X(0x18) X(0xf0) X(0x7d) X(0xec) X(0x3a) X(0xdc) X(0x4d) X(0x20) \
    X(0x79) X(0xee) X(0x5f) X(0x3e) X(0xd7) X(0xcb) X(0x39) X(0x48)
/* clang-format on */

#define SM4_L(b) ((b) ^ ROL32((b), 2) ^ ROL32((b), 10) ^ ROL32((b), 18) ^ ROL32((b), 24))
#define SM4_T0_ENTRY(s) SM4_L((uint32_t)(s) << 24),
#define SM4_T1_ENTRY(s) SM4_L((uint32_t)(s) << 16),
#define SM4_T2_ENTRY(s) SM4_L((uint32_t)(s) << 8),
#define SM4_T3_ENTRY(s) SM4_L((uint32_t)(s)),
#define SM4_LK(b) ((b) ^ ROL32((b), 13) ^ ROL32((b), 23))
#define SM4_K0_ENTRY(s) SM4_LK((uint32_t)(s) << 24),
#define SM4_K1_ENTRY(s) SM4_LK((uint32_t)(s) << 16),
#define SM4_K2_ENTRY(s) SM4_LK((uint32_t)(s) << 8),
#define SM4_K3_ENTRY(s) SM4_LK((uint32_t)(s)),

#if defined(__GNUC__)
#define SM4_ALIGNED __attribute__((aligned(64)))
#else
#define SM4_ALIGNED
#endif

/* T_i[x] = L(S(x) << 8 (3 - i)): one round is four lookups and three XORs. */
static const uint32_t sm4_t0[256] SM4_ALIGNED = {SM4_SBOX_LIST(SM4_T0_ENTRY)};
static const uint32_t sm4_t1[256] SM4_ALIGNED = {SM4_SBOX_LIST(SM4_T1_ENTRY)};
static const uint32_t sm4_t2[256] SM4_ALIGNED = {SM4_SBOX_LIST(SM4_T2_ENTRY)};
static const uint32_t sm4_t3[256] SM4_ALIGNED = {SM4_SBOX_LIST(SM4_T3_ENTRY)};
/* K_i[x] = L'(S(x) << 8 (3 - i)), the same for the key schedule's linear map */
static const uint32_t sm4_k0[256] SM4_ALIGNED = {SM4_SBOX_LIST(SM4_K0_ENTRY)};
static const uint32_t sm4_k1[256] SM4_ALIGNED = {SM4_SBOX_LIST(SM4_K1_ENTRY)};
static const uint32_t sm4_k2[256] SM4_ALIGNED = {SM4_SBOX_LIST(SM4_K2_ENTRY)};
static const uint32_t sm4_k3[256] SM4_ALIGNED = {SM4_SBOX_LIST(SM4_K3_ENTRY)};

/* ---- table path ---- */

#define SM4_TT(x)                                                                                  \
    (sm4_t0[(x) >> 24] ^ sm4_t1[((x) >> 16) & 0xFF] ^ sm4_t2[((x) >> 8) & 0xFF] ^                  \
     sm4_t3[(x) & 0xFF])
#define SM4_TROUND(A, B, C, D, K)                                                                  \
    do {                                                                                           \
        uint32_t t_ = (B) ^ (C) ^ (D) ^ (K);                                                       \
        (A) ^= SM4_TT(t_);                                                                         \
    } while (0)
#define SM4_TROUNDS4(A, B, C, D, RK, I)                                                            \
    SM4_TROUND(A, B, C, D, (RK)[(I)]);                                                             \
    SM4_TROUND(B, C, D, A, (RK)[(I) + 1]);                                                         \
    SM4_TROUND(C, D, A, B, (RK)[(I) + 2]);                                                         \
    SM4_TROUND(D, A, B, C, (RK)[(I) + 3])
/* All 32 rounds, unrolled; the output is (D, C, B, A). */
#define SM4_TROUNDS32(A, B, C, D, RK)                                                              \
    SM4_TROUNDS4(A, B, C, D, RK, 0);                                                               \
    SM4_TROUNDS4(A, B, C, D, RK, 4);                                                               \
    SM4_TROUNDS4(A, B, C, D, RK, 8);                                                               \
    SM4_TROUNDS4(A, B, C, D, RK, 12);                                                              \
    SM4_TROUNDS4(A, B, C, D, RK, 16);                                                              \
    SM4_TROUNDS4(A, B, C, D, RK, 20);                                                              \
    SM4_TROUNDS4(A, B, C, D, RK, 24);                                                              \
    SM4_TROUNDS4(A, B, C, D, RK, 28)

/* One block. */
static void sm4_table_block(const uint32_t rk[32], const uint8_t *in, uint8_t *out) {
    uint32_t a = smx_load_be32(in), b = smx_load_be32(in + 4);
    uint32_t c = smx_load_be32(in + 8), d = smx_load_be32(in + 12);
    SM4_TROUNDS32(a, b, c, d, rk);
    smx_store_be32(out, d);
    smx_store_be32(out + 4, c);
    smx_store_be32(out + 8, b);
    smx_store_be32(out + 12, a);
}

/*
 * SM4_TABLE_WAYS independent blocks with their rounds interleaved: one block's rounds are a
 * chain of dependent loads, and the CPU can run several chains side by side.
 */
#ifndef SM4_TABLE_WAYS
#define SM4_TABLE_WAYS 4
#endif

#define SM4_TABLE_WAYS_ROUND(A, B, C, D, K)                                                        \
    for (j = 0; j < SM4_TABLE_WAYS; j++) {                                                         \
        SM4_TROUND(A[j], B[j], C[j], D[j], K);                                                     \
    }

static void sm4_table_blocks(const uint32_t rk[32], const uint8_t *in, uint8_t *out) {
    uint32_t a[SM4_TABLE_WAYS], b[SM4_TABLE_WAYS], c[SM4_TABLE_WAYS], d[SM4_TABLE_WAYS];
    int i, j;
    for (j = 0; j < SM4_TABLE_WAYS; j++) {
        a[j] = smx_load_be32(in + j * 16);
        b[j] = smx_load_be32(in + j * 16 + 4);
        c[j] = smx_load_be32(in + j * 16 + 8);
        d[j] = smx_load_be32(in + j * 16 + 12);
    }
    for (i = 0; i < 32; i += 4) {
        SM4_TABLE_WAYS_ROUND(a, b, c, d, rk[i])
        SM4_TABLE_WAYS_ROUND(b, c, d, a, rk[i + 1])
        SM4_TABLE_WAYS_ROUND(c, d, a, b, rk[i + 2])
        SM4_TABLE_WAYS_ROUND(d, a, b, c, rk[i + 3])
    }
    for (j = 0; j < SM4_TABLE_WAYS; j++) {
        smx_store_be32(out + j * 16, d[j]);
        smx_store_be32(out + j * 16 + 4, c[j]);
        smx_store_be32(out + j * 16 + 8, b[j]);
        smx_store_be32(out + j * 16 + 12, a[j]);
    }
}

/* CBC encryption is serial, one block after the other. */
static void sm4_table_cbc_encrypt(const uint32_t rk[32], uint32_t iv[4], const uint8_t *in,
                                  size_t blocks, char *hex) {
    uint32_t a = iv[0], b = iv[1], c = iv[2], d = iv[3], t;
    uint8_t ct[16];
    for (; blocks > 0; blocks--, in += 16, hex += 32) {
        a ^= smx_load_be32(in);
        b ^= smx_load_be32(in + 4);
        c ^= smx_load_be32(in + 8);
        d ^= smx_load_be32(in + 12);
        SM4_TROUNDS32(a, b, c, d, rk);
        /* the final reversal */
        t = a;
        a = d;
        d = t;
        t = b;
        b = c;
        c = t;
        smx_store_be32(ct, a);
        smx_store_be32(ct + 4, b);
        smx_store_be32(ct + 8, c);
        smx_store_be32(ct + 12, d);
        smx_hex_encode(ct, 16, hex, 'a');
    }
    iv[0] = a;
    iv[1] = b;
    iv[2] = c;
    iv[3] = d;
    sm4_wipe(ct, sizeof(ct));
}

/* ---- x86 paths ---- */

#ifdef SMX_SM4_X86

/* "unused": a lower SMX_SM4_MAX_TIER leaves the faster implementations unreferenced */
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
 * The linear layer, x ^ rol(x, 24) ^ rol(x ^ rol(x, 8) ^ rol(x, 16), 2), shared by the two
 * tiers through a macro because functions with different targets cannot inline one another.
 */
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

TARGET_AESNI256
    static void sm4_aesni256_blocks(const uint32_t rk[32], const uint8_t *in, uint8_t *out) {
    SM4_CRYPT8_BODY(sm4_aesni_tau_256)
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

/*
 * SM4_NEON_SETS groups of four blocks side by side: one group's rounds are a dependency chain
 * that leaves most of the vector units idle.
 */
#ifndef SM4_NEON_SETS
#define SM4_NEON_SETS 8
#endif

static void sm4_neon_blocks(const uint32_t rk[32], const uint8_t *in, uint8_t *out) {
    uint32x4_t a[SM4_NEON_SETS], b[SM4_NEON_SETS], c[SM4_NEON_SETS], d[SM4_NEON_SETS];
    int i, j;
    for (j = 0; j < SM4_NEON_SETS; j++) {
        uint32x4x4_t v = vld4q_u32((const uint32_t *)(const void *)(in + j * 64));
        a[j] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v.val[0])));
        b[j] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v.val[1])));
        c[j] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v.val[2])));
        d[j] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v.val[3])));
    }
    for (i = 0; i < 32; i += 4) {
        for (j = 0; j < SM4_NEON_SETS; j++) {
            SM4_NEON_ROUND(a[j], b[j], c[j], d[j], rk[i]);
        }
        for (j = 0; j < SM4_NEON_SETS; j++) {
            SM4_NEON_ROUND(b[j], c[j], d[j], a[j], rk[i + 1]);
        }
        for (j = 0; j < SM4_NEON_SETS; j++) {
            SM4_NEON_ROUND(c[j], d[j], a[j], b[j], rk[i + 2]);
        }
        for (j = 0; j < SM4_NEON_SETS; j++) {
            SM4_NEON_ROUND(d[j], a[j], b[j], c[j], rk[i + 3]);
        }
    }
    for (j = 0; j < SM4_NEON_SETS; j++) {
        uint32x4x4_t v;
        v.val[0] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(d[j])));
        v.val[1] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(c[j])));
        v.val[2] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(b[j])));
        v.val[3] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(a[j])));
        vst4q_u32((uint32_t *)(void *)(out + j * 64), v);
    }
}

#endif /* SMX_SM4_NEON */

/* ---- dispatch ---- */

typedef void (*Sm4BlocksFn)(const uint32_t rk[32], const uint8_t *in, uint8_t *out);

#define SM4_MAX_LANES 32
typedef char sm4_table_ways_fit[SM4_TABLE_WAYS <= SM4_MAX_LANES ? 1 : -1];

/*
 * Rough costs, measured on an Intel i5-13500H and an Apple M2, in tenths of one block through
 * the tables: a group of SM4_TABLE_WAYS interleaved table blocks, and one (possibly padded)
 * call of each multi-block primitive. They decide how the blocks that do not fill a whole
 * batch are handled.
 */
#define SM4_COST_ONE 10
#if defined(__aarch64__)
#define SM4_COST_WAYS 14
#else
#define SM4_COST_WAYS 17
#endif
#define SM4_COST_GFNI 18
#define SM4_COST_AESNI256 32
#define SM4_COST_NEON 45

static size_t sm4_table_cost(size_t blocks) {
    return blocks / SM4_TABLE_WAYS * SM4_COST_WAYS + blocks % SM4_TABLE_WAYS * SM4_COST_ONE;
}

/*
 * The multi-block primitive for CBC decryption, its width, and its cost. Written only before
 * main() runs, so it needs no synchronization.
 */
#ifdef SMX_SM4_NEON
typedef char sm4_neon_lanes_fit[4 * SM4_NEON_SETS <= SM4_MAX_LANES ? 1 : -1];
static const Sm4BlocksFn sm4_blocks = sm4_neon_blocks;
static const size_t sm4_lanes = 4 * SM4_NEON_SETS;
static const size_t sm4_batch_cost = SM4_COST_NEON * SM4_NEON_SETS / 8;
#else
static Sm4BlocksFn sm4_blocks = sm4_table_blocks;
static size_t sm4_lanes = SM4_TABLE_WAYS;
static size_t sm4_batch_cost = SM4_COST_WAYS;
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
        sm4_lanes = 8;
        sm4_batch_cost = SM4_COST_GFNI;
        return;
    }
#endif
    if (avx2 && aes && ssse3) {
        sm4_blocks = sm4_aesni256_blocks;
        sm4_lanes = 8;
        sm4_batch_cost = SM4_COST_AESNI256;
    }
}
#endif

/* ---- key schedule ---- */

/* Marks a context as holding a valid key; anything else is refused. */
#define SM4_KEY_SET 0x534D3421u

static inline uint32_t sm4_key_t(uint32_t x) {
    return sm4_k0[x >> 24] ^ sm4_k1[(x >> 16) & 0xFF] ^ sm4_k2[(x >> 8) & 0xFF] ^ sm4_k3[x & 0xFF];
}

static void sm4_expand_key(SM4 *ctx, const uint8_t key[16]) {
    uint32_t k0 = smx_load_be32(key) ^ sm4_fk[0];
    uint32_t k1 = smx_load_be32(key + 4) ^ sm4_fk[1];
    uint32_t k2 = smx_load_be32(key + 8) ^ sm4_fk[2];
    uint32_t k3 = smx_load_be32(key + 12) ^ sm4_fk[3];
    int i;

    for (i = 0; i < 32; i += 4) {
        k0 ^= sm4_key_t(k1 ^ k2 ^ k3 ^ sm4_ck[i]);
        k1 ^= sm4_key_t(k2 ^ k3 ^ k0 ^ sm4_ck[i + 1]);
        k2 ^= sm4_key_t(k3 ^ k0 ^ k1 ^ sm4_ck[i + 2]);
        k3 ^= sm4_key_t(k0 ^ k1 ^ k2 ^ sm4_ck[i + 3]);
        ctx->rk[i] = k0;
        ctx->rk[i + 1] = k1;
        ctx->rk[i + 2] = k2;
        ctx->rk[i + 3] = k3;
    }
    sm4_wipe(&k0, sizeof(k0));
    sm4_wipe(&k1, sizeof(k1));
    sm4_wipe(&k2, sizeof(k2));
    sm4_wipe(&k3, sizeof(k3));
}

/* ---- public API ---- */

void sm4_init(SM4 *ctx) {
    if (ctx != NULL) {
        sm4_wipe(ctx, sizeof(SM4));
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
    sm4_wipe(ctx, sizeof(SM4));
    if (!valid) {
        return; /* the context stays unset, and encrypt and decrypt return NULL */
    }
    sm4_expand_key(ctx, key_copy);
    memcpy(ctx->iv, iv_copy, 16);
    ctx->key_state = SM4_KEY_SET;
    sm4_wipe(key_copy, sizeof(key_copy));
    sm4_wipe(iv_copy, sizeof(iv_copy));
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
        sm4_table_cbc_encrypt(ctx->rk, iv, data, full_blocks, hex);
    }
    memset(last, (int)(16 - tail), 16);
    if (tail > 0) {
        memcpy(last, data + full_blocks * 16, tail);
    }
    sm4_table_cbc_encrypt(ctx->rk, iv, last, 1, hex + full_blocks * 32);
    hex[total * 2] = '\0';
    sm4_wipe(last, sizeof(last));
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
        } else if (sm4_table_cost(count) > sm4_batch_cost) {
            memset(partial, 0, sizeof(partial));
            memcpy(partial, buf + start * 16, count * 16);
            sm4_blocks(rk, partial, tmp);
        } else {
            /* too few blocks to pay for a whole batch */
            for (j = 0; j + SM4_TABLE_WAYS <= count; j += SM4_TABLE_WAYS) {
                sm4_table_blocks(rk, buf + (start + j) * 16, tmp + j * 16);
            }
            if ((count - j) * SM4_COST_ONE > SM4_COST_WAYS) {
                /* two or three left: one padded interleaved call is cheaper */
                memset(partial, 0, SM4_TABLE_WAYS * 16);
                memcpy(partial, buf + (start + j) * 16, (count - j) * 16);
                sm4_table_blocks(rk, partial, tmp + j * 16);
            } else {
                for (; j < count; j++) {
                    sm4_table_block(rk, buf + (start + j) * 16, tmp + j * 16);
                }
            }
        }
        for (j = count; j > 0; j--) {
            size_t index = start + j - 1;
            const uint8_t *prev = index == 0 ? ctx->iv : buf + (index - 1) * 16;
            xor_block(buf + index * 16, tmp + (j - 1) * 16, prev);
        }
        blocks = start;
    }
    sm4_wipe(rk, sizeof(rk));
    sm4_wipe(tmp, sizeof(tmp));
    sm4_wipe(partial, sizeof(partial));
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

void smx_sm4_ecb_encrypt(const uint8_t key[16], const uint8_t *in, uint8_t *out, size_t blocks) {
    SM4 ctx;
    size_t i;
    sm4_expand_key(&ctx, key);
    for (i = 0; i < blocks; i++) {
        sm4_table_block(ctx.rk, in + 16 * i, out + 16 * i);
    }
    sm4_wipe(&ctx, sizeof(ctx));
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
    for (i = 0; i < len / 16; i++) {
        sm4_table_block(rk, buf + 16 * i, buf + 16 * i);
    }
    sm4_wipe(&ctx, sizeof(ctx));
    sm4_wipe(rk, sizeof(rk));
    return pkcs7_check(buf, len, plain_len);
}
