/*
 * SM9 arithmetic modulo the BN prime q and modulo the group order N, both in Montgomery
 * form (a * 2^256 mod m) on four little-endian 64-bit limbs.
 *
 * q and N have no special form and both exceed 2^255, so every reduction keeps the carry
 * out of the top limb. Every function here is constant time: no branch and no memory access
 * depends on a value. Exponents (inversion) are public. Inputs and outputs are fully reduced.
 *
 * Internal header, included by sm9.c and the tests.
 */
#ifndef SMX_SM9_FP_H
#define SMX_SM9_FP_H

#include "smx_internal.h"
#include "sm9_const.h"
#include <string.h>

typedef struct {
    uint64_t v[4];
} fq_t;

static const fq_t FQ_ZERO = {{0, 0, 0, 0}};
static const fq_t FQ_ONE = SM9_FQ_ONE_INIT;

/* r = (top : v) minus m once if that does not go negative. */
static inline void sm9_reduce_once(uint64_t r[4], const uint64_t v[4], uint64_t top,
                                   const uint64_t m[4]) {
    uint64_t b;
    uint64_t t0 = smx_subb(v[0], m[0], 0, &b);
    uint64_t t1 = smx_subb(v[1], m[1], b, &b);
    uint64_t t2 = smx_subb(v[2], m[2], b, &b);
    uint64_t t3 = smx_subb(v[3], m[3], b, &b);
    uint64_t keep = smx_mask_from_bit(b & (top ^ 1));
    r[0] = t0 ^ (keep & (t0 ^ v[0]));
    r[1] = t1 ^ (keep & (t1 ^ v[1]));
    r[2] = t2 ^ (keep & (t2 ^ v[2]));
    r[3] = t3 ^ (keep & (t3 ^ v[3]));
}

#define SM9_MONT_ROUND(t0, t1, t2, t3, m, m0)                                                      \
    do {                                                                                           \
        uint64_t qq = (t0) * (m0);                                                                 \
        (void)smx_mac(qq, (m)[0], (t0), 0, &c);                                                    \
        (t1) = smx_mac(qq, (m)[1], (t1), c, &c);                                                   \
        (t2) = smx_mac(qq, (m)[2], (t2), c, &c);                                                   \
        (t3) = smx_mac(qq, (m)[3], (t3), c, &c);                                                   \
    } while (0)

/*
 * Montgomery reduction of x < m * 2^256: x / 2^256 mod m, fully reduced. Straight-line code,
 * so no compiler can turn the carry handling into branches.
 */
static inline SMX_ALWAYS_INLINE void sm9_mont_reduce(uint64_t r[4], const uint64_t x[8],
                                                     const uint64_t m[4], uint64_t m0) {
    uint64_t t0 = x[0], t1 = x[1], t2 = x[2], t3 = x[3];
    uint64_t t4 = x[4], t5 = x[5], t6 = x[6], t7 = x[7];
    uint64_t c, top, v[4];

    SM9_MONT_ROUND(t0, t1, t2, t3, m, m0);
    t4 = smx_addc(t4, c, 0, &c);
    t5 = smx_addc(t5, 0, c, &c);
    t6 = smx_addc(t6, 0, c, &c);
    t7 = smx_addc(t7, 0, c, &c);
    top = c;

    SM9_MONT_ROUND(t1, t2, t3, t4, m, m0);
    t5 = smx_addc(t5, c, 0, &c);
    t6 = smx_addc(t6, 0, c, &c);
    t7 = smx_addc(t7, 0, c, &c);
    top += c;

    SM9_MONT_ROUND(t2, t3, t4, t5, m, m0);
    t6 = smx_addc(t6, c, 0, &c);
    t7 = smx_addc(t7, 0, c, &c);
    top += c;

    SM9_MONT_ROUND(t3, t4, t5, t6, m, m0);
    t7 = smx_addc(t7, c, 0, &c);
    top += c;

    v[0] = t4;
    v[1] = t5;
    v[2] = t6;
    v[3] = t7;
    sm9_reduce_once(r, v, top, m);
}

/*
 * Montgomery product a * b / 2^256 mod m for a, b < m, interleaving each row of the product
 * with one reduction step (CIOS). The running value stays below 2m, so its fifth limb is 0 or 1;
 * this measured about twice as fast as a full product followed by sm9_mont_reduce.
 */
#define SM9_CIOS_ROW(bi)                                                                           \
    do {                                                                                           \
        t0 = smx_mac(a[0], (bi), t0, 0, &c);                                                       \
        t1 = smx_mac(a[1], (bi), t1, c, &c);                                                       \
        t2 = smx_mac(a[2], (bi), t2, c, &c);                                                       \
        t3 = smx_mac(a[3], (bi), t3, c, &c);                                                       \
        t4 = smx_addc(t4, c, 0, &c2);                                                              \
        q = t0 * m0;                                                                               \
        (void)smx_mac(q, m[0], t0, 0, &c);                                                         \
        t0 = smx_mac(q, m[1], t1, c, &c);                                                          \
        t1 = smx_mac(q, m[2], t2, c, &c);                                                          \
        t2 = smx_mac(q, m[3], t3, c, &c);                                                          \
        t3 = smx_addc(t4, c, 0, &c);                                                               \
        t4 = c2 + c;                                                                               \
    } while (0)

static inline SMX_ALWAYS_INLINE void sm9_mont_mul(uint64_t r[4], const uint64_t a[4],
                                                  const uint64_t b[4], const uint64_t m[4],
                                                  uint64_t m0) {
    uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, c, c2, q, v[4];
    uint64_t b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3];
    SM9_CIOS_ROW(b0);
    SM9_CIOS_ROW(b1);
    SM9_CIOS_ROW(b2);
    SM9_CIOS_ROW(b3);
    v[0] = t0;
    v[1] = t1;
    v[2] = t2;
    v[3] = t3;
    sm9_reduce_once(r, v, t4, m);
}

/* ---------------------------------------------------------------- Fq */

static inline void fq_mul(fq_t *r, const fq_t *a, const fq_t *b) {
    sm9_mont_mul(r->v, a->v, b->v, SM9_Q, SM9_Q0);
}

static inline void fq_sqr(fq_t *r, const fq_t *a) {
    sm9_mont_mul(r->v, a->v, a->v, SM9_Q, SM9_Q0);
}

static inline void fq_add(fq_t *r, const fq_t *a, const fq_t *b) {
    uint64_t v[4], c;
    v[0] = smx_addc(a->v[0], b->v[0], 0, &c);
    v[1] = smx_addc(a->v[1], b->v[1], c, &c);
    v[2] = smx_addc(a->v[2], b->v[2], c, &c);
    v[3] = smx_addc(a->v[3], b->v[3], c, &c);
    sm9_reduce_once(r->v, v, c, SM9_Q);
}

static inline void fq_sub(fq_t *r, const fq_t *a, const fq_t *b) {
    smx_mod_sub(r->v, a->v, b->v, SM9_Q);
}

static inline void fq_dbl(fq_t *r, const fq_t *a) {
    fq_add(r, a, a);
}

/* -a, canonical for a == 0 */
static inline void fq_neg(fq_t *r, const fq_t *a) {
    smx_mod_sub(r->v, FQ_ZERO.v, a->v, SM9_Q);
}

/* r = mask ? a : r, mask all ones or zero */
static inline void fq_cmov(fq_t *r, const fq_t *a, uint64_t mask) {
    r->v[0] ^= mask & (r->v[0] ^ a->v[0]);
    r->v[1] ^= mask & (r->v[1] ^ a->v[1]);
    r->v[2] ^= mask & (r->v[2] ^ a->v[2]);
    r->v[3] ^= mask & (r->v[3] ^ a->v[3]);
}

/* all ones if a == 0 */
static inline uint64_t fq_is_zero(const fq_t *a) {
    return smx_mask_is_zero(a->v[0] | a->v[1] | a->v[2] | a->v[3]);
}

static inline uint64_t fq_equal(const fq_t *a, const fq_t *b) {
    return smx_mask_is_zero((a->v[0] ^ b->v[0]) | (a->v[1] ^ b->v[1]) | (a->v[2] ^ b->v[2]) |
                            (a->v[3] ^ b->v[3]));
}

/* r = a^e for a public exponent e, by a fixed 4-bit window over its digits. */
static inline void sm9_mont_pow(uint64_t r[4], const uint64_t a[4], const uint64_t e[4],
                                const uint64_t one[4], const uint64_t m[4], uint64_t m0) {
    uint64_t pow[16][4], w[8];
    int i, j;
    memcpy(pow[0], one, 32);
    memcpy(pow[1], a, 32);
    for (i = 2; i < 16; i++) {
        smx_mul_4x4(w, pow[i - 1], a);
        sm9_mont_reduce(pow[i], w, m, m0);
    }
    memcpy(r, one, 32);
    for (i = 63; i >= 0; i--) {
        unsigned digit = (unsigned)(e[i / 16] >> ((i % 16) * 4)) & 15u;
        for (j = 0; j < 4; j++) {
            smx_sqr_4(w, r);
            sm9_mont_reduce(r, w, m, m0);
        }
        smx_mul_4x4(w, r, pow[digit]); /* the digit is public: the exponent is a constant */
        sm9_mont_reduce(r, w, m, m0);
    }
    smx_wipe(pow, sizeof(pow));
    smx_wipe(w, sizeof(w));
}

/* r = 1/a by Fermat; inverting 0 gives 0 */
static inline void fq_inv(fq_t *r, const fq_t *a) {
    sm9_mont_pow(r->v, a->v, SM9_Q_MINUS_2, FQ_ONE.v, SM9_Q, SM9_Q0);
}

/* Montgomery form of a value below q, and back */
static inline void fq_to_mont(fq_t *r, const uint64_t a[4]) {
    uint64_t w[8];
    smx_mul_4x4(w, a, SM9_Q_R2);
    sm9_mont_reduce(r->v, w, SM9_Q, SM9_Q0);
}

static inline void fq_from_mont(uint64_t r[4], const fq_t *a) {
    uint64_t w[8] = {0};
    memcpy(w, a->v, 32);
    sm9_mont_reduce(r, w, SM9_Q, SM9_Q0);
}

/* 32 big-endian bytes; returns all ones if the value is below q (and then converts it) */
static inline uint64_t fq_from_bytes(fq_t *r, const uint8_t in[32]) {
    uint64_t v[4], b;
    int i;
    for (i = 0; i < 4; i++) {
        v[i] = smx_load_be64(in + 24 - 8 * i);
    }
    (void)smx_subb(v[0], SM9_Q[0], 0, &b);
    (void)smx_subb(v[1], SM9_Q[1], b, &b);
    (void)smx_subb(v[2], SM9_Q[2], b, &b);
    (void)smx_subb(v[3], SM9_Q[3], b, &b);
    fq_to_mont(r, v);
    smx_wipe(v, sizeof(v));
    return smx_mask_from_bit(b);
}

static inline void fq_to_bytes(uint8_t out[32], const fq_t *a) {
    uint64_t v[4];
    int i;
    fq_from_mont(v, a);
    for (i = 0; i < 4; i++) {
        smx_store_be64(out + 24 - 8 * i, v[i]);
    }
    smx_wipe(v, sizeof(v));
}

/* ---------------------------------------------------------------- integers mod N */

/* plain (not Montgomery) values in [0, N) */
static inline void sm9n_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t w[8], am[4];
    smx_mul_4x4(w, a, SM9_N_R2);
    sm9_mont_reduce(am, w, SM9_N, SM9_N0);
    smx_mul_4x4(w, am, b);
    sm9_mont_reduce(r, w, SM9_N, SM9_N0);
    smx_wipe(am, sizeof(am));
    smx_wipe(w, sizeof(w));
}

/* 1/a mod N for a in [0, N); 0 gives 0 */
static inline void sm9n_inv(uint64_t r[4], const uint64_t a[4]) {
    static const uint64_t one[4] = {1, 0, 0, 0};
    uint64_t w[8], am[4], one_m[4], t[4];
    smx_mul_4x4(w, a, SM9_N_R2);
    sm9_mont_reduce(am, w, SM9_N, SM9_N0);
    smx_mul_4x4(w, one, SM9_N_R2);
    sm9_mont_reduce(one_m, w, SM9_N, SM9_N0);
    sm9_mont_pow(t, am, SM9_N_MINUS_2, one_m, SM9_N, SM9_N0);
    memset(w, 0, sizeof(w));
    memcpy(w, t, 32);
    sm9_mont_reduce(r, w, SM9_N, SM9_N0);
    smx_wipe(am, sizeof(am));
    smx_wipe(t, sizeof(t));
    smx_wipe(w, sizeof(w));
}

/* all ones if 1 <= a <= N - 1 */
static inline uint64_t sm9n_in_range(const uint64_t a[4]) {
    uint64_t b;
    (void)smx_subb(a[0], SM9_N[0], 0, &b);
    (void)smx_subb(a[1], SM9_N[1], b, &b);
    (void)smx_subb(a[2], SM9_N[2], b, &b);
    (void)smx_subb(a[3], SM9_N[3], b, &b);
    return smx_mask_from_bit(b) & ~smx_mask_is_zero(a[0] | a[1] | a[2] | a[3]);
}

#endif /* SMX_SM9_FP_H */
