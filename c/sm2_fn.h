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
    uint64_t keep = (uint64_t)0 - (b & (top ^ 1));
    r[0] = t0 ^ (keep & (t0 ^ v[0]));
    r[1] = t1 ^ (keep & (t1 ^ v[1]));
    r[2] = t2 ^ (keep & (t2 ^ v[2]));
    r[3] = t3 ^ (keep & (t3 ^ v[3]));
}

/* Montgomery reduction of t < n * R; result is t / R mod n, fully reduced. */
static inline void fn_mont_reduce(uint64_t r[4], const uint64_t x[8]) {
    uint64_t t[8], top = 0;
    int i;
    for (i = 0; i < 8; i++) {
        t[i] = x[i];
    }
    for (i = 0; i < 4; i++) {
        uint64_t q = t[i] * FN_N0;
        uint64_t c;
        int j;
        (void)smx_mac(q, FN_N[0], t[i], 0, &c);
        t[i + 1] = smx_mac(q, FN_N[1], t[i + 1], c, &c);
        t[i + 2] = smx_mac(q, FN_N[2], t[i + 2], c, &c);
        t[i + 3] = smx_mac(q, FN_N[3], t[i + 3], c, &c);
        for (j = i + 4; j < 8; j++) {
            t[j] = smx_addc(t[j], c, 0, &c);
        }
        top += c;
    }
    fn_reduce_once(r, t + 4, top);
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
 * The exponent is public, so skipping zero digits and indexing the power table
 * by the exponent leak nothing about the base.
 *   n-2 = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54121
 */
static inline void fn_inv(uint64_t r[4], const uint64_t a[4]) {
    static const uint64_t low_digits[2] = {0x53BBF40939D54121ULL, 0x7203DF6B21C6052BULL};
    uint64_t pow[16][4], x8[4], x16[4], x32[4], t[4], one[4] = {1, 0, 0, 0}, ra[4];
    int i;

    fn_reduce(ra, a);
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
        if (digit != 0) {
            fn_mont_mul(t, t, pow[digit]);
        }
    }

    fn_mont_mul(r, t, one); /* leave Montgomery form */
}

#endif /* SMX_SM2_FN_H */
