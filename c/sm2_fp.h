/*
 * Arithmetic modulo the SM2 prime p = 2^256 - 2^224 - 2^96 + 2^64 - 1.
 *
 * Every function here is constant time: no branch and no memory access depends
 * on a value. Inputs and outputs are fully reduced, in [0, p).
 *
 * Internal header, included by bigint256.c, sm2.c and the tests.
 */
#ifndef SMX_SM2_FP_H
#define SMX_SM2_FP_H

#include "smx_internal.h"

typedef uint64_t Fe[4];

static const Fe FE_P = {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFFFFFFFFFFULL,
                        0xFFFFFFFEFFFFFFFFULL};
static const Fe FE_ONE = {1, 0, 0, 0};

static inline void fe_copy(Fe r, const Fe a) {
    r[0] = a[0];
    r[1] = a[1];
    r[2] = a[2];
    r[3] = a[3];
}

/* r = mask ? a : r, where mask is all ones or zero. */
static inline void fe_cmov(Fe r, const Fe a, uint64_t mask) {
    r[0] ^= mask & (r[0] ^ a[0]);
    r[1] ^= mask & (r[1] ^ a[1]);
    r[2] ^= mask & (r[2] ^ a[2]);
    r[3] ^= mask & (r[3] ^ a[3]);
}

/* All ones if a == 0, otherwise zero. */
static inline uint64_t fe_is_zero(const Fe a) {
    return smx_mask_is_zero(a[0] | a[1] | a[2] | a[3]);
}

/* All ones if a == b, otherwise zero. */
static inline uint64_t fe_equal(const Fe a, const Fe b) {
    return smx_mask_is_zero((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3]));
}

/* r = (top : v) mod p for a value below 2p, subtracting p when it fits. */
static inline void fe_reduce_once(Fe r, const uint64_t v[4], uint64_t top) {
    uint64_t b;
    uint64_t t0 = smx_subb(v[0], FE_P[0], 0, &b);
    uint64_t t1 = smx_subb(v[1], FE_P[1], b, &b);
    uint64_t t2 = smx_subb(v[2], FE_P[2], b, &b);
    uint64_t t3 = smx_subb(v[3], FE_P[3], b, &b);
    /* keep v only when the subtraction borrowed past the top word */
    uint64_t keep = smx_mask_from_bit(b & (top ^ 1));
    r[0] = t0 ^ (keep & (t0 ^ v[0]));
    r[1] = t1 ^ (keep & (t1 ^ v[1]));
    r[2] = t2 ^ (keep & (t2 ^ v[2]));
    r[3] = t3 ^ (keep & (t3 ^ v[3]));
}

/*
 * r = (top * 2^256 + v) mod p for a small top, using
 * 2^256 = 2^224 + 2^96 - 2^64 + 1 (mod p).
 *
 * The fold adds less than 2^(224 + bits(top) + 1), so with top < 2^5 the sum stays
 * below 2^256 + 2^230 < 2p, including its carry. One conditional subtraction then
 * finishes the job.
 */
static inline void fe_fold(Fe r, const uint64_t in[4], uint64_t top) {
    uint64_t v[4], c;
    v[0] = smx_addc(in[0], top, 0, &c);
    v[1] = smx_addc(in[1], (top << 32) - top, c, &c);
    v[2] = smx_addc(in[2], 0, c, &c);
    v[3] = smx_addc(in[3], top << 32, c, &c);
    fe_reduce_once(r, v, c);
}

/*
 * Solinas reduction of a 512-bit value. Writing the high half as 32-bit words
 * c8..c15 and folding each with 2^256 = 2^224 + 2^96 - 2^64 + 1 gives a column
 * sum per 32-bit position. Only column 2 subtracts anything, so 16p is added
 * across the columns (with 8 * 2^32 moved from column 3 into column 2) and all
 * the arithmetic can stay in unsigned 64-bit, with no signed shifts and no
 * 128-bit type required.
 */
static inline void fe_reduce_wide(Fe r, const uint64_t x[8]) {
    const uint64_t m = 0xFFFFFFFFu;
    uint64_t c8 = x[4] & m, c9 = x[4] >> 32, c10 = x[5] & m, c11 = x[5] >> 32;
    uint64_t c12 = x[6] & m, c13 = x[6] >> 32, c14 = x[7] & m, c15 = x[7] >> 32;
    uint64_t s9_11 = c9 + c10 + c11;
    uint64_t s12_13 = c12 + c13;
    uint64_t s14_15 = c14 + c15;
    const uint64_t off = 16 * m;
    uint64_t a0 = (x[0] & m) + off + c8 + s9_11 + s12_13 + c13 + 2 * s14_15;
    uint64_t a1 = (x[0] >> 32) + off + s9_11 + s12_13 + 2 * s14_15;
    uint64_t a2 = (x[1] & m) + ((uint64_t)8 << 32) - c8 - c9 - c13 - c14;
    uint64_t a3 = (x[1] >> 32) + off - 8 + c8 + c11 + s12_13 + c13 + s14_15;
    uint64_t a4 = (x[2] & m) + off + c9 + s12_13 + s14_15 + c14;
    uint64_t a5 = (x[2] >> 32) + off + c10 + c13 + s14_15 + c15;
    uint64_t a6 = (x[3] & m) + off + c11 + s14_15;
    uint64_t a7 =
        (x[3] >> 32) + 16 * (uint64_t)0xFFFFFFFEu + c8 + s9_11 + 2 * (s12_13 + c14) + 3 * c15;
    uint64_t v[4];

    a1 += a0 >> 32;
    a2 += a1 >> 32;
    a3 += a2 >> 32;
    a4 += a3 >> 32;
    a5 += a4 >> 32;
    a6 += a5 >> 32;
    a7 += a6 >> 32;

    v[0] = (a0 & m) | (a1 << 32);
    v[1] = (a2 & m) | (a3 << 32);
    v[2] = (a4 & m) | (a5 << 32);
    v[3] = (a6 & m) | (a7 << 32);
    fe_fold(r, v, a7 >> 32);
}

static inline void fe_mul(Fe r, const Fe a, const Fe b) {
    uint64_t w[8];
    smx_mul_4x4(w, a, b);
    fe_reduce_wide(r, w);
}

static inline void fe_sqr(Fe r, const Fe a) {
    uint64_t w[8];
    smx_sqr_4(w, a);
    fe_reduce_wide(r, w);
}

static inline void fe_add(Fe r, const Fe a, const Fe b) {
    uint64_t v[4], c;
    v[0] = smx_addc(a[0], b[0], 0, &c);
    v[1] = smx_addc(a[1], b[1], c, &c);
    v[2] = smx_addc(a[2], b[2], c, &c);
    v[3] = smx_addc(a[3], b[3], c, &c);
    fe_reduce_once(r, v, c);
}

static inline void fe_sub(Fe r, const Fe a, const Fe b) {
    uint64_t v[4], c, mask;
    v[0] = smx_subb(a[0], b[0], 0, &c);
    v[1] = smx_subb(a[1], b[1], c, &c);
    v[2] = smx_subb(a[2], b[2], c, &c);
    v[3] = smx_subb(a[3], b[3], c, &c);
    mask = smx_mask_from_bit(c);
    r[0] = smx_addc(v[0], FE_P[0] & mask, 0, &c);
    r[1] = smx_addc(v[1], FE_P[1] & mask, c, &c);
    r[2] = smx_addc(v[2], FE_P[2] & mask, c, &c);
    r[3] = smx_addc(v[3], FE_P[3] & mask, c, &c);
}

/* r = m * a for a small constant m <= 16. */
static inline void fe_mul_small(Fe r, const Fe a, uint64_t m) {
    uint64_t v[4], c;
    v[0] = smx_mac(a[0], m, 0, 0, &c);
    v[1] = smx_mac(a[1], m, 0, c, &c);
    v[2] = smx_mac(a[2], m, 0, c, &c);
    v[3] = smx_mac(a[3], m, 0, c, &c);
    fe_fold(r, v, c);
}

/* r = -a if mask is all ones, otherwise r = a; stays canonical for a == 0. */
static inline void fe_cond_neg(Fe r, const Fe a, uint64_t mask) {
    uint64_t v[4], b;
    uint64_t nonzero = ~fe_is_zero(a);
    v[0] = smx_subb(FE_P[0], a[0], 0, &b);
    v[1] = smx_subb(FE_P[1], a[1], b, &b);
    v[2] = smx_subb(FE_P[2], a[2], b, &b);
    v[3] = smx_subb(FE_P[3], a[3], b, &b);
    mask &= nonzero;
    r[0] = a[0] ^ (mask & (a[0] ^ v[0]));
    r[1] = a[1] ^ (mask & (a[1] ^ v[1]));
    r[2] = a[2] ^ (mask & (a[2] ^ v[2]));
    r[3] = a[3] ^ (mask & (a[3] ^ v[3]));
}

static inline void fe_sqr_n(Fe r, const Fe a, int n) {
    int i;
    fe_sqr(r, a);
    for (i = 1; i < n; i++) {
        fe_sqr(r, r);
    }
}

/*
 * r = a^(p-2) by a fixed addition chain (255 squarings, 14 multiplications).
 * The exponent is public, the base is not; inverting 0 gives 0.
 * In binary p-2 is: 31 ones, a zero, 128 ones, 32 zeros, 62 ones, then 01.
 */
static inline void fe_inv(Fe r, const Fe a) {
    Fe x2, x3, x6, x12, x24, x30, x31, x32, x62, x64, x128, t;

    fe_sqr(x2, a);
    fe_mul(x2, x2, a);
    fe_sqr(x3, x2);
    fe_mul(x3, x3, a);
    fe_sqr_n(x6, x3, 3);
    fe_mul(x6, x6, x3);
    fe_sqr_n(x12, x6, 6);
    fe_mul(x12, x12, x6);
    fe_sqr_n(x24, x12, 12);
    fe_mul(x24, x24, x12);
    fe_sqr_n(x30, x24, 6);
    fe_mul(x30, x30, x6);
    fe_sqr(x31, x30);
    fe_mul(x31, x31, a);
    fe_sqr(x32, x31);
    fe_mul(x32, x32, a);
    fe_sqr_n(x62, x32, 30);
    fe_mul(x62, x62, x30);
    fe_sqr_n(x64, x62, 2);
    fe_mul(x64, x64, x2);
    fe_sqr_n(x128, x64, 64);
    fe_mul(x128, x128, x64);

    fe_sqr(t, x31); /* the zero after the first 31 ones */
    fe_sqr_n(t, t, 128);
    fe_mul(t, t, x128);
    fe_sqr_n(t, t, 32); /* 32 zeros */
    fe_sqr_n(t, t, 62);
    fe_mul(t, t, x62);
    fe_sqr_n(t, t, 2);
    fe_mul(r, t, a);
}

#endif /* SMX_SM2_FP_H */
