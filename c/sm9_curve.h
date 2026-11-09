/*
 * SM9 groups: G1 = E(Fq), E: y^2 = x^3 + 5, prime order N (cofactor 1), and G2, the order-N
 * subgroup of the twist E'(Fq2): y^2 = x^3 + 5u, which has a cofactor, so G2 points read from
 * outside need the subgroup check below.
 *
 * Scalar multiplication:
 *   g1_mul_ct, g2_mul_ct  constant time, fixed signed window with a full masked table scan
 *   g1_mul_vt, g2_mul_vt  variable time wNAF, PUBLIC scalars only
 *
 * Internal header, included by sm9.c and the tests.
 */
#ifndef SMX_SM9_CURVE_H
#define SMX_SM9_CURVE_H

#include "sm9_tower.h"

#define SM9_WIN_BITS 5
#define SM9_WIN_ENTRIES (1 << (SM9_WIN_BITS - 1))
#define SM9_WIN_COUNT (256 / SM9_WIN_BITS + 1)

typedef struct {
    fq_t x, y, z;
} g1_t;

typedef struct {
    fq2_t x, y, z;
} g2_t;

/* Signed window digit i (Booth recoding), as ec_booth_digit in sm2_ec.h. */
static inline unsigned sm9_booth_digit(const uint64_t k[4], int i, uint64_t *negative) {
    const int bits = SM9_WIN_BITS;
    const uint64_t mask = ((uint64_t)1 << (bits + 1)) - 1;
    uint64_t w, sign, d;
    if (i == 0) {
        w = (k[0] << 1) & mask;
    } else {
        int off = bits * i - 1;
        int limb = off / 64, shift = off % 64;
        w = k[limb] >> shift;
        if (shift > 64 - (bits + 1) && limb < 3) {
            w |= k[limb + 1] << (64 - shift);
        }
        w &= mask;
    }
    sign = smx_mask_from_bit(w >> bits);
    d = ((uint64_t)1 << (bits + 1)) - w - 1;
    d = (d & sign) | (w & ~sign);
    *negative = sign;
    return (unsigned)((d >> 1) + (d & 1));
}

/* Width-5 NAF of a public k, least significant digit first; returns the digit count. */
static inline int sm9_wnaf(int8_t out[258], const uint64_t k_in[4]) {
    uint64_t k[5];
    int len = 0;
    memcpy(k, k_in, 32);
    k[4] = 0;
    while ((k[0] | k[1] | k[2] | k[3] | k[4]) != 0) {
        int digit = 0;
        if ((k[0] & 1) != 0) {
            uint64_t low = k[0] & 31, c;
            if (low >= 16) {
                digit = (int)low - 32;
                k[0] = smx_addc(k[0], 32 - low, 0, &c);
                k[1] = smx_addc(k[1], 0, c, &c);
                k[2] = smx_addc(k[2], 0, c, &c);
                k[3] = smx_addc(k[3], 0, c, &c);
                k[4] += c;
            } else {
                digit = (int)low;
                k[0] -= low;
            }
        }
        out[len++] = (int8_t)digit;
        k[0] = (k[0] >> 1) | (k[1] << 63);
        k[1] = (k[1] >> 1) | (k[2] << 63);
        k[2] = (k[2] >> 1) | (k[3] << 63);
        k[3] = (k[3] >> 1) | (k[4] << 63);
        k[4] >>= 1;
    }
    return len;
}

static inline void fq_set_one(fq_t *r) {
    *r = FQ_ONE;
}

#define PT g1_t
#define FE fq_t
#define PT_FN(name) g1_##name
#define FE_ADD fq_add
#define FE_SUB fq_sub
#define FE_DBL fq_dbl
#define FE_MUL fq_mul
#define FE_SQR fq_sqr
#define FE_NEG fq_neg
#define FE_CMOV fq_cmov
#define FE_IS_ZERO fq_is_zero
#define FE_EQUAL fq_equal
#define FE_ONE_SET fq_set_one
#include "sm9_point.inc"
#undef PT
#undef FE
#undef PT_FN
#undef FE_ADD
#undef FE_SUB
#undef FE_DBL
#undef FE_MUL
#undef FE_SQR
#undef FE_NEG
#undef FE_CMOV
#undef FE_IS_ZERO
#undef FE_EQUAL
#undef FE_ONE_SET

#define PT g2_t
#define FE fq2_t
#define PT_FN(name) g2_##name
#define FE_ADD fq2_add
#define FE_SUB fq2_sub
#define FE_DBL fq2_dbl
#define FE_MUL fq2_mul
#define FE_SQR fq2_sqr
#define FE_NEG fq2_neg
#define FE_CMOV fq2_cmov
#define FE_IS_ZERO fq2_is_zero
#define FE_EQUAL fq2_equal
#define FE_ONE_SET fq2_set_one
#include "sm9_point.inc"
#undef PT
#undef FE
#undef PT_FN
#undef FE_ADD
#undef FE_SUB
#undef FE_DBL
#undef FE_MUL
#undef FE_SQR
#undef FE_NEG
#undef FE_CMOV
#undef FE_IS_ZERO
#undef FE_EQUAL
#undef FE_ONE_SET

static const fq_t SM9_FQ_FIVE = SM9_FQ_FIVE_INIT;
static const g1_t SM9_P1 = {SM9_P1_X_INIT, SM9_P1_Y_INIT, SM9_FQ_ONE_INIT};
static const g2_t SM9_P2 = {SM9_P2_X_INIT, SM9_P2_Y_INIT, {SM9_FQ_ONE_INIT, {{0, 0, 0, 0}}}};
static const fq_t SM9_PI_X = SM9_PI_X_INIT;
static const fq_t SM9_PI_Y = SM9_PI_Y_INIT;

/* affine coordinates; infinity gives (0, 0) */
static inline void g1_to_affine(fq_t *x, fq_t *y, const g1_t *p) {
    fq_t zi, zi2;
    fq_inv(&zi, &p->z);
    fq_sqr(&zi2, &zi);
    fq_mul(x, &p->x, &zi2);
    fq_mul(&zi2, &zi2, &zi);
    fq_mul(y, &p->y, &zi2);
}

static inline void g2_to_affine(fq2_t *x, fq2_t *y, const g2_t *p) {
    fq2_t zi, zi2;
    fq2_inv(&zi, &p->z);
    fq2_sqr(&zi2, &zi);
    fq2_mul(x, &p->x, &zi2);
    fq2_mul(&zi2, &zi2, &zi);
    fq2_mul(y, &p->y, &zi2);
}

/* all ones if (x, y) is on E: y^2 = x^3 + 5 */
static inline uint64_t g1_affine_on_curve(const fq_t *x, const fq_t *y) {
    fq_t l, r;
    fq_sqr(&l, y);
    fq_sqr(&r, x);
    fq_mul(&r, &r, x);
    fq_add(&r, &r, &SM9_FQ_FIVE);
    return fq_equal(&l, &r);
}

/* all ones if (x, y) is on E': y^2 = x^3 + 5u */
static inline uint64_t g2_affine_on_curve(const fq2_t *x, const fq2_t *y) {
    fq2_t l, r;
    fq2_sqr(&l, y);
    fq2_sqr(&r, x);
    fq2_mul(&r, &r, x);
    fq_add(&r.a1, &r.a1, &SM9_FQ_FIVE);
    return fq2_equal(&l, &r);
}

/* psi: the Frobenius of E(Fq12) carried to the twist; Jacobian in, Jacobian out */
static inline void g2_frob(g2_t *r, const g2_t *p) {
    fq2_conj(&r->x, &p->x);
    fq2_mul_fq(&r->x, &r->x, &SM9_PI_X);
    fq2_conj(&r->y, &p->y);
    fq2_mul_fq(&r->y, &r->y, &SM9_PI_Y);
    fq2_conj(&r->z, &p->z);
}

/*
 * Membership in G2 for a point already on the twist. On all of E'(Fq2), psi satisfies
 * psi^2 - tr psi + q = 0 with tr = 6t^2 + 1 the trace of E over Fq, so
 *   [N]Q = [q + 1 - tr]Q = [tr](psi(Q) - Q) - psi^2(Q) + Q,
 * and [N]Q = O exactly when [tr](psi(Q) - Q) = psi^2(Q) - Q: a 128-bit multiplication instead
 * of a 256-bit one. tr is public; for points of G2 no addition in it meets a == b, so the
 * branches in add_vt depend only on whether the point is valid.
 */
static inline uint64_t g2_in_subgroup(const g2_t *q) {
    g2_t psi, psi2, nq, lhs, rhs;
    uint64_t ok;
    g2_frob(&psi, q);
    g2_frob(&psi2, &psi);
    g2_neg(&nq, q);
    g2_add_vt(&lhs, &psi, &nq);
    g2_mul_vt(&lhs, &lhs, SM9_TRACE);
    g2_add_vt(&rhs, &psi2, &nq);
    ok = g2_equal(&lhs, &rhs);
    smx_wipe(&psi, sizeof(psi));
    smx_wipe(&psi2, sizeof(psi2));
    smx_wipe(&nq, sizeof(nq));
    smx_wipe(&lhs, sizeof(lhs));
    smx_wipe(&rhs, sizeof(rhs));
    return ok;
}

/*
 * 04 || x || y. Returns all ones for a valid point: coordinates below q, on the curve (which
 * excludes infinity, having no affine form). Constant time, so a secret point may pass.
 */
static inline uint64_t g1_from_bytes(g1_t *r, const uint8_t in[65]) {
    uint64_t ok = smx_mask_is_zero((uint64_t)(in[0] ^ 0x04));
    ok &= fq_from_bytes(&r->x, in + 1);
    ok &= fq_from_bytes(&r->y, in + 33);
    ok &= g1_affine_on_curve(&r->x, &r->y);
    r->z = FQ_ONE;
    return ok;
}

/* 04 || x1 || x0 || y1 || y0, then the subgroup check (only reached for points on the twist) */
static inline uint64_t g2_from_bytes(g2_t *r, const uint8_t in[129]) {
    uint64_t ok = smx_mask_is_zero((uint64_t)(in[0] ^ 0x04));
    ok &= fq_from_bytes(&r->x.a1, in + 1);
    ok &= fq_from_bytes(&r->x.a0, in + 33);
    ok &= fq_from_bytes(&r->y.a1, in + 65);
    ok &= fq_from_bytes(&r->y.a0, in + 97);
    ok &= g2_affine_on_curve(&r->x, &r->y);
    fq2_set_one(&r->z);
    SMX_DECLASSIFY(&ok, sizeof(ok));
    if (ok) {
        ok = g2_in_subgroup(r);
        SMX_DECLASSIFY(&ok, sizeof(ok));
    }
    return ok;
}

/* x || y of an affine point, 64 bytes */
static inline void g1_affine_to_bytes(uint8_t out[64], const fq_t *x, const fq_t *y) {
    fq_to_bytes(out, x);
    fq_to_bytes(out + 32, y);
}

static inline void g2_affine_to_bytes(uint8_t out[128], const fq2_t *x, const fq2_t *y) {
    fq_to_bytes(out, &x->a1);
    fq_to_bytes(out + 32, &x->a0);
    fq_to_bytes(out + 64, &y->a1);
    fq_to_bytes(out + 96, &y->a0);
}

#endif /* SMX_SM9_CURVE_H */
