/*
 * Arithmetic modulo the SM2 group order n, used for signing and key exchange,
 * where the operands include the private key and the nonce. Uses Montgomery
 * reduction; n has no helpful special form. Constant time throughout.
 *
 * Internal header, included by sm2.c and the tests.
 */
#ifndef SMX_SM2_FN_H
#define SMX_SM2_FN_H

#include "smx_internal.h"

static const uint64_t FN_N[4] = {0x53BBF40939D54123ULL, 0x7203DF6B21C6052BULL,
                                 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL};
/* R^2 mod n, with R = 2^256 */
static const uint64_t FN_R2[4] = {0x901192AF7C114F20ULL, 0x3464504ADE6FA2FAULL,
                                  0x620FC84C3AFFE0D4ULL, 0x1EB5E412A22B3D3BULL};
/* -1/n mod 2^64 */
#define FN_N0 0x327F9E8872350975ULL

/* r = (top : v) minus n once if that does not go negative. */
static inline void fn_reduce_once(uint64_t r[4], const uint64_t v[4], uint64_t top) {
    uint64_t b;
    uint64_t t0 = smx_subb(v[0], FN_N[0], 0, &b);
    uint64_t t1 = smx_subb(v[1], FN_N[1], b, &b);
    uint64_t t2 = smx_subb(v[2], FN_N[2], b, &b);
    uint64_t t3 = smx_subb(v[3], FN_N[3], b, &b);
    uint64_t keep = smx_ct_barrier((uint64_t)0 - (b & (top ^ 1)));
    r[0] = t0 ^ (keep & (t0 ^ v[0]));
    r[1] = t1 ^ (keep & (t1 ^ v[1]));
    r[2] = t2 ^ (keep & (t2 ^ v[2]));
    r[3] = t3 ^ (keep & (t3 ^ v[3]));
}

/*
 * One Montgomery round: clears t[0] and adds into t[1..4], returning the carry out of t[3]
 * and t[4] for the caller's next limb.
 */
#define FN_MONT_ROUND(t0, t1, t2, t3)                                                              \
    do {                                                                                           \
        uint64_t q = (t0) * FN_N0;                                                                 \
        (void)smx_mac(q, FN_N[0], (t0), 0, &c);                                                    \
        (t1) = smx_mac(q, FN_N[1], (t1), c, &c);                                                   \
        (t2) = smx_mac(q, FN_N[2], (t2), c, &c);                                                   \
        (t3) = smx_mac(q, FN_N[3], (t3), c, &c);                                                   \
    } while (0)

/*
 * Montgomery reduction of t < n * R; result is t / R mod n, fully reduced. Straight-line
 * code: a loop over the carry limbs lets a compiler unroll it into forward branches.
 */
static inline void fn_mont_reduce(uint64_t r[4], const uint64_t x[8]) {
    uint64_t t0 = x[0], t1 = x[1], t2 = x[2], t3 = x[3];
    uint64_t t4 = x[4], t5 = x[5], t6 = x[6], t7 = x[7];
    uint64_t c, top, v[4];

    FN_MONT_ROUND(t0, t1, t2, t3);
    t4 = smx_addc(t4, c, 0, &c);
    t5 = smx_addc(t5, 0, c, &c);
    t6 = smx_addc(t6, 0, c, &c);
    t7 = smx_addc(t7, 0, c, &c);
    top = c;

    FN_MONT_ROUND(t1, t2, t3, t4);
    t5 = smx_addc(t5, c, 0, &c);
    t6 = smx_addc(t6, 0, c, &c);
    t7 = smx_addc(t7, 0, c, &c);
    top += c;

    FN_MONT_ROUND(t2, t3, t4, t5);
    t6 = smx_addc(t6, c, 0, &c);
    t7 = smx_addc(t7, 0, c, &c);
    top += c;

    FN_MONT_ROUND(t3, t4, t5, t6);
    t7 = smx_addc(t7, c, 0, &c);
    top += c;

    v[0] = t4;
    v[1] = t5;
    v[2] = t6;
    v[3] = t7;
    fn_reduce_once(r, v, top);
}

/* Montgomery product a * b / R mod n, for a, b < n. */
static inline void fn_mont_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t w[8];
    smx_mul_4x4(w, a, b);
    fn_mont_reduce(r, w);
}

static inline void fn_mont_sqr(uint64_t r[4], const uint64_t a[4]) {
    uint64_t w[8];
    smx_sqr_4(w, a);
    fn_mont_reduce(r, w);
}

static inline void fn_mont_sqr_n(uint64_t r[4], const uint64_t a[4], int n) {
    int i;
    fn_mont_sqr(r, a);
    for (i = 1; i < n; i++) {
        fn_mont_sqr(r, r);
    }
}

/* r = a mod n for any 256-bit a: 2^256 < 2n, so one subtraction is enough. */
static inline void fn_reduce(uint64_t r[4], const uint64_t a[4]) {
    fn_reduce_once(r, a, 0);
}

/* r = a * b mod n, for any 256-bit a and b. */
static inline void fn_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t ra[4], rb[4], am[4];
    fn_reduce(ra, a);
    fn_reduce(rb, b);
    fn_mont_mul(am, ra, FN_R2);
    fn_mont_mul(r, am, rb);
}

/*
 * r = a^(n-2) mod n, for any 256-bit a; inverting a multiple of n gives 0.
 * The exponent is public, so indexing the power table by its digits leaks nothing about
 * the base.
 *   n-2 = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54121
 */
static inline void fn_inv(uint64_t r[4], const uint64_t a[4]) {
    static const uint64_t low_digits[2] = {0x53BBF40939D54121ULL, 0x7203DF6B21C6052BULL};
    uint64_t pow[16][4], x8[4], x16[4], x32[4], t[4], one[4] = {1, 0, 0, 0}, ra[4];
    int i;

    fn_reduce(ra, a);
    fn_mont_mul(pow[0], one, FN_R2);
    fn_mont_mul(pow[1], ra, FN_R2);
    for (i = 2; i < 16; i++) {
        fn_mont_mul(pow[i], pow[i - 1], pow[1]);
    }

    /* pow[15] has 4 ones; build runs of 8, 16 and 32 ones */
    fn_mont_sqr_n(x8, pow[15], 4);
    fn_mont_mul(x8, x8, pow[15]);
    fn_mont_sqr_n(x16, x8, 8);
    fn_mont_mul(x16, x16, x8);
    fn_mont_sqr_n(x32, x16, 16);
    fn_mont_mul(x32, x32, x16);

    /* FFFFFFFE = 28 ones, then E */
    fn_mont_sqr_n(t, x16, 8);
    fn_mont_mul(t, t, x8);
    fn_mont_sqr_n(t, t, 4);
    fn_mont_mul(t, t, pow[15]);
    fn_mont_sqr_n(t, t, 4);
    fn_mont_mul(t, t, pow[14]);
    for (i = 0; i < 3; i++) {
        fn_mont_sqr_n(t, t, 32);
        fn_mont_mul(t, t, x32);
    }

    for (i = 124; i >= 0; i -= 4) {
        unsigned digit = (unsigned)(low_digits[i / 64] >> (i % 64)) & 15u;
        fn_mont_sqr_n(t, t, 4);
        fn_mont_mul(t, t, pow[digit]); /* pow[0] is the Montgomery form of 1 */
    }

    fn_mont_mul(r, t, one); /* leave Montgomery form */
}

#endif /* SMX_SM2_FN_H */
