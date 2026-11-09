/*
 * The SM9 R-ate pairing e: G1 x G2 -> GT, and exponentiation in GT. Constant time: the Miller
 * loop and the final exponentiation follow public constants only, so a secret G2 point (a user
 * encryption key) or a secret G1 point is safe to pass.
 *
 *   Miller loop over a = 6t + 2 with T in Jacobian coordinates on the twist, lines evaluated at
 *   P and multiplied in sparse form (only w^0, w^2 and w^3 are nonzero), then T += pi(Q),
 *   T -= pi^2(Q). Each line is scaled by a factor of Fq2, which the final exponentiation removes.
 *   Final exponentiation f^((q^12 - 1) / N): the easy part f^((q^6 - 1)(q^2 + 1)), then the hard
 *   part (q^4 - q^2 + 1) / N by the chain of Scott et al. through f^t, f^(t^2), f^(t^3), with
 *   cyclotomic squarings.
 *
 * The degenerate additions of a general Miller loop cannot happen: T is [k]Q for 1 < k < N on
 * the way, and [6t + 2]Q and [6t + 2 + q]Q at the last two lines, never +-Q, +-pi(Q) or
 * +-pi^2(Q) for Q of order N. Identity inputs are handled by the caller (e(P, Q) = 1).
 *
 * Internal header, included by sm9.c and the tests.
 */
#ifndef SMX_SM9_PAIRING_H
#define SMX_SM9_PAIRING_H

#include "sm9_curve.h"

typedef struct {
    fq_t x, y_neg; /* P, with -y ready for the lines */
} sm9_line_point;

/* T = 2T, and the tangent line at T evaluated at P: c0 + c2 w^2 + c3 w^3 */
static inline void sm9_dbl_step(g2_t *t, fq12_t *f, const sm9_line_point *p) {
    fq2_t a, b, c, d, e, ff, zz, c0, c2, c3, tmp;
    fq2_sqr(&a, &t->x);
    fq2_sqr(&b, &t->y);
    fq2_sqr(&c, &b);
    fq2_add(&d, &t->x, &b);
    fq2_sqr(&d, &d);
    fq2_sub(&d, &d, &a);
    fq2_sub(&d, &d, &c);
    fq2_dbl(&d, &d);
    fq2_dbl(&e, &a);
    fq2_add(&e, &e, &a);
    fq2_sqr(&ff, &e);
    fq2_sqr(&zz, &t->z);

    /* the line, from the old T */
    fq2_dbl(&c0, &b);
    fq2_mul(&tmp, &e, &t->x);
    fq2_sub(&c0, &c0, &tmp);
    fq2_mul(&c2, &e, &zz);
    fq2_mul_fq(&c2, &c2, &p->x);

    /* Z3 = 2YZ, X3 = F - 2D, Y3 = E(D - X3) - 8C */
    fq2_mul(&tmp, &t->y, &t->z);
    fq2_dbl(&t->z, &tmp);
    fq2_dbl(&tmp, &d);
    fq2_sub(&t->x, &ff, &tmp);
    fq2_sub(&tmp, &d, &t->x);
    fq2_mul(&tmp, &e, &tmp);
    fq2_dbl(&c, &c);
    fq2_dbl(&c, &c);
    fq2_dbl(&c, &c);
    fq2_sub(&t->y, &tmp, &c);

    fq2_mul(&c3, &t->z, &zz);
    fq2_mul_fq(&c3, &c3, &p->y_neg);
    fq12_mul_line(f, &c0, &c2, &c3);
}

/* T = T + Q for an affine Q, and the line through them evaluated at P */
static inline void sm9_add_step(g2_t *t, fq12_t *f, const fq2_t *xq, const fq2_t *yq,
                                const sm9_line_point *p) {
    fq2_t zz, u2, s2, h, r, hh, hhh, v, c0, c2, c3, tmp;
    fq2_sqr(&zz, &t->z);
    fq2_mul(&u2, xq, &zz);
    fq2_mul(&s2, yq, &t->z);
    fq2_mul(&s2, &s2, &zz);
    fq2_sub(&h, &u2, &t->x);
    fq2_sub(&r, &s2, &t->y);
    fq2_sqr(&hh, &h);
    fq2_mul(&hhh, &hh, &h);
    fq2_mul(&v, &t->x, &hh);

    fq2_sqr(&tmp, &r);
    fq2_sub(&tmp, &tmp, &hhh);
    fq2_sub(&tmp, &tmp, &v);
    fq2_sub(&tmp, &tmp, &v);
    fq2_sub(&v, &v, &tmp);
    t->x = tmp;
    fq2_mul(&v, &r, &v);
    fq2_mul(&hhh, &t->y, &hhh);
    fq2_sub(&t->y, &v, &hhh);
    fq2_mul(&t->z, &t->z, &h);

    fq2_mul(&c0, yq, &t->z);
    fq2_mul(&tmp, &r, xq);
    fq2_sub(&c0, &c0, &tmp);
    fq2_mul_fq(&c2, &r, &p->x);
    fq2_mul_fq(&c3, &t->z, &p->y_neg);
    fq12_mul_line(f, &c0, &c2, &c3);
}

static inline void sm9_miller_loop(fq12_t *f, const fq_t *xp, const fq_t *yp, const fq2_t *xq,
                                   const fq2_t *yq) {
    sm9_line_point p;
    g2_t t;
    fq2_t x1, y1, x2, y2;
    int i;

    p.x = *xp;
    fq_neg(&p.y_neg, yp);
    t.x = *xq;
    t.y = *yq;
    fq2_set_one(&t.z);
    fq12_set_one(f);
    /* a = 6t + 2 has 66 bits; the top one is the starting T = Q */
    for (i = 64; i >= 0; i--) {
        uint64_t bit = i >= 64 ? (SM9_ATE_LOOP_HI >> (i - 64)) & 1 : (SM9_ATE_LOOP_LO >> i) & 1;
        fq12_sqr(f, f);
        sm9_dbl_step(&t, f, &p);
        if (bit) {
            sm9_add_step(&t, f, xq, yq, &p);
        }
    }
    /* pi(Q) and -pi^2(Q), affine */
    fq2_conj(&x1, xq);
    fq2_mul_fq(&x1, &x1, &SM9_PI_X);
    fq2_conj(&y1, yq);
    fq2_mul_fq(&y1, &y1, &SM9_PI_Y);
    fq2_conj(&x2, &x1);
    fq2_mul_fq(&x2, &x2, &SM9_PI_X);
    fq2_conj(&y2, &y1);
    fq2_mul_fq(&y2, &y2, &SM9_PI_Y);
    fq2_neg(&y2, &y2);
    sm9_add_step(&t, f, &x1, &y1, &p);
    sm9_add_step(&t, f, &x2, &y2, &p);
    smx_wipe(&t, sizeof(t));
    smx_wipe(&p, sizeof(p));
}

/* r = f^t in the cyclotomic subgroup; t is public */
static inline void sm9_cyclo_pow_t(fq12_t *r, const fq12_t *f) {
    fq12_t acc = *f;
    int i;
    for (i = 61; i >= 0; i--) {
        fq12_cyclo_sqr(&acc, &acc);
        if (((SM9_T >> i) & 1) != 0) {
            fq12_mul(&acc, &acc, f);
        }
    }
    *r = acc;
    smx_wipe(&acc, sizeof(acc));
}

static inline void sm9_final_exp(fq12_t *r, const fq12_t *f_in) {
    fq12_t f, t, fx, fx2, fx3, y0, y1, y2, y3, y4, y5, y6, t0, t1;

    /* easy part: f^(q^6 - 1), then ^(q^2 + 1) */
    fq12_inv(&t, f_in);
    fq12_conj(&f, f_in);
    fq12_mul(&f, &f, &t);
    fq12_frob(&t, &f, 2);
    fq12_mul(&f, &t, &f);

    /* hard part */
    sm9_cyclo_pow_t(&fx, &f);
    sm9_cyclo_pow_t(&fx2, &fx);
    sm9_cyclo_pow_t(&fx3, &fx2);

    fq12_frob(&y0, &f, 1);
    fq12_frob(&t, &f, 2);
    fq12_mul(&y0, &y0, &t);
    fq12_frob(&t, &f, 3);
    fq12_mul(&y0, &y0, &t);
    fq12_conj(&y1, &f);
    fq12_frob(&y2, &fx2, 2);
    fq12_frob(&y3, &fx, 1);
    fq12_conj(&y3, &y3);
    fq12_frob(&y4, &fx2, 1);
    fq12_mul(&y4, &y4, &fx);
    fq12_conj(&y4, &y4);
    fq12_conj(&y5, &fx2);
    fq12_frob(&y6, &fx3, 1);
    fq12_mul(&y6, &y6, &fx3);
    fq12_conj(&y6, &y6);

    fq12_cyclo_sqr(&t0, &y6);
    fq12_mul(&t0, &t0, &y4);
    fq12_mul(&t0, &t0, &y5);
    fq12_mul(&t1, &y3, &y5);
    fq12_mul(&t1, &t1, &t0);
    fq12_mul(&t0, &t0, &y2);
    fq12_cyclo_sqr(&t1, &t1);
    fq12_mul(&t1, &t1, &t0);
    fq12_cyclo_sqr(&t1, &t1);
    fq12_mul(&t0, &t1, &y1);
    fq12_mul(&t1, &t1, &y0);
    fq12_cyclo_sqr(&t0, &t0);
    fq12_mul(r, &t1, &t0);

    smx_wipe(&f, sizeof(f));
    smx_wipe(&t, sizeof(t));
    smx_wipe(&fx, sizeof(fx));
    smx_wipe(&fx2, sizeof(fx2));
    smx_wipe(&fx3, sizeof(fx3));
    smx_wipe(&y0, sizeof(y0));
    smx_wipe(&y1, sizeof(y1));
    smx_wipe(&y2, sizeof(y2));
    smx_wipe(&y3, sizeof(y3));
    smx_wipe(&y4, sizeof(y4));
    smx_wipe(&y5, sizeof(y5));
    smx_wipe(&y6, sizeof(y6));
    smx_wipe(&t0, sizeof(t0));
    smx_wipe(&t1, sizeof(t1));
}

/* e(P, Q) for affine P in G1 and Q in G2; neither may be infinity */
static inline void sm9_pairing(fq12_t *r, const fq_t *xp, const fq_t *yp, const fq2_t *xq,
                               const fq2_t *yq) {
    fq12_t f;
    sm9_miller_loop(&f, xp, yp, xq, yq);
    sm9_final_exp(r, &f);
    smx_wipe(&f, sizeof(f));
}

#define SM9_GT_WIN 4
#define SM9_GT_ENTRIES (1 << SM9_GT_WIN)

/* Reads every entry, whichever one is wanted; local sum as in the point table scans. */
static SMX_NOINLINE void sm9_gt_select(fq12_t *sel, const fq12_t table[SM9_GT_ENTRIES],
                                       unsigned digit) {
    uint64_t acc[sizeof(fq12_t) / sizeof(uint64_t)];
    const size_t words = sizeof(fq12_t) / sizeof(uint64_t);
    size_t j, l;
    for (l = 0; l < words; l++) {
        acc[l] = 0;
    }
    for (j = 0; j < SM9_GT_ENTRIES; j++) {
        const uint64_t *in = (const uint64_t *)&table[j];
        uint64_t mask = smx_mask_is_zero((uint64_t)(digit ^ (unsigned)j));
        for (l = 0; l < words; l++) {
            acc[l] |= in[l] & mask;
        }
    }
    memcpy(sel, acc, sizeof(acc));
    smx_wipe(acc, sizeof(acc));
}

/*
 * r = g^k for g in GT (the cyclotomic subgroup) and any 256-bit k, constant time in k: a fixed
 * 4-bit window, every table entry read for every digit, and a multiplication even by g^0 = 1.
 */
static inline void sm9_gt_pow(fq12_t *r, const fq12_t *g, const uint64_t k[4]) {
    fq12_t table[SM9_GT_ENTRIES], acc, sel;
    int i, j;
    fq12_set_one(&table[0]);
    table[1] = *g;
    for (i = 2; i < SM9_GT_ENTRIES; i++) {
        fq12_mul(&table[i], &table[i - 1], g);
    }
    fq12_set_one(&acc);
    for (i = 63; i >= 0; i--) {
        unsigned digit = (unsigned)(k[i / 16] >> ((i % 16) * 4)) & 15u;
        for (j = 0; j < SM9_GT_WIN; j++) {
            fq12_cyclo_sqr(&acc, &acc);
        }
        sm9_gt_select(&sel, table, digit);
        fq12_mul(&acc, &acc, &sel);
    }
    *r = acc;
    smx_wipe(table, sizeof(table));
    smx_wipe(&acc, sizeof(acc));
    smx_wipe(&sel, sizeof(sel));
}

#endif /* SMX_SM9_PAIRING_H */
