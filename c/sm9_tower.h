/*
 * SM9 extension fields, all constant time:
 *   Fq2  = Fq[u]  / (u^2 + 2)
 *   Fq6  = Fq2[s] / (s^3 - u)
 *   Fq12 = Fq6[w] / (w^2 - s)
 * so w^6 = u and an Fq12 element is sum x_j w^j with x_j in Fq2: c[0] holds x0, x2, x4 and
 * c[1] holds x1, x3, x5. The standard's tower Fq4 = Fq2[v] / (v^2 - u), Fq12 = Fq4[w] / (w^3 - v)
 * is the same field with v = w^3, which is what the byte encoding and the cyclotomic squaring use.
 *
 * Internal header, included by sm9.c and the tests.
 */
#ifndef SMX_SM9_TOWER_H
#define SMX_SM9_TOWER_H

#include "sm9_fp.h"

typedef struct {
    fq_t a0, a1; /* a0 + a1 u */
} fq2_t;

typedef struct {
    fq2_t c[3]; /* c0 + c1 s + c2 s^2 */
} fq6_t;

typedef struct {
    fq6_t c[2]; /* c0 + c1 w */
} fq12_t;

/* ---------------------------------------------------------------- Fq2 */

static inline void fq2_add(fq2_t *r, const fq2_t *a, const fq2_t *b) {
    fq_add(&r->a0, &a->a0, &b->a0);
    fq_add(&r->a1, &a->a1, &b->a1);
}

static inline void fq2_sub(fq2_t *r, const fq2_t *a, const fq2_t *b) {
    fq_sub(&r->a0, &a->a0, &b->a0);
    fq_sub(&r->a1, &a->a1, &b->a1);
}

static inline void fq2_dbl(fq2_t *r, const fq2_t *a) {
    fq_dbl(&r->a0, &a->a0);
    fq_dbl(&r->a1, &a->a1);
}

static inline void fq2_neg(fq2_t *r, const fq2_t *a) {
    fq_neg(&r->a0, &a->a0);
    fq_neg(&r->a1, &a->a1);
}

static inline void fq2_conj(fq2_t *r, const fq2_t *a) {
    r->a0 = a->a0;
    fq_neg(&r->a1, &a->a1);
}

/* Karatsuba, with u^2 = -2: 3 multiplications */
static inline void fq2_mul(fq2_t *r, const fq2_t *a, const fq2_t *b) {
    fq_t t0, t1, sa, sb, t2;
    fq_mul(&t0, &a->a0, &b->a0);
    fq_mul(&t1, &a->a1, &b->a1);
    fq_add(&sa, &a->a0, &a->a1);
    fq_add(&sb, &b->a0, &b->a1);
    fq_mul(&t2, &sa, &sb);
    fq_sub(&t2, &t2, &t0);
    fq_sub(&r->a1, &t2, &t1);
    fq_dbl(&t1, &t1);
    fq_sub(&r->a0, &t0, &t1);
}

/* (a0 + a1 u)^2 = (a0 + a1)(a0 - 2 a1) + a0 a1 + 2 a0 a1 u: 2 multiplications */
static inline void fq2_sqr(fq2_t *r, const fq2_t *a) {
    fq_t t, s, d;
    fq_mul(&t, &a->a0, &a->a1);
    fq_add(&s, &a->a0, &a->a1);
    fq_dbl(&d, &a->a1);
    fq_sub(&d, &a->a0, &d);
    fq_mul(&s, &s, &d);
    fq_add(&r->a0, &s, &t);
    fq_dbl(&r->a1, &t);
}

/* r = a * u = -2 a1 + a0 u */
static inline void fq2_mul_u(fq2_t *r, const fq2_t *a) {
    fq_t t;
    fq_dbl(&t, &a->a1);
    r->a1 = a->a0;
    fq_neg(&r->a0, &t);
}

static inline void fq2_mul_fq(fq2_t *r, const fq2_t *a, const fq_t *k) {
    fq_mul(&r->a0, &a->a0, k);
    fq_mul(&r->a1, &a->a1, k);
}

static inline void fq2_inv(fq2_t *r, const fq2_t *a) {
    fq_t n, t;
    fq_sqr(&n, &a->a0);
    fq_sqr(&t, &a->a1);
    fq_dbl(&t, &t);
    fq_add(&n, &n, &t);
    fq_inv(&n, &n);
    fq_mul(&r->a0, &a->a0, &n);
    fq_mul(&t, &a->a1, &n);
    fq_neg(&r->a1, &t);
}

static inline void fq2_cmov(fq2_t *r, const fq2_t *a, uint64_t mask) {
    fq_cmov(&r->a0, &a->a0, mask);
    fq_cmov(&r->a1, &a->a1, mask);
}

static inline uint64_t fq2_is_zero(const fq2_t *a) {
    return fq_is_zero(&a->a0) & fq_is_zero(&a->a1);
}

static inline uint64_t fq2_equal(const fq2_t *a, const fq2_t *b) {
    return fq_equal(&a->a0, &b->a0) & fq_equal(&a->a1, &b->a1);
}

static inline void fq2_set_zero(fq2_t *r) {
    r->a0 = FQ_ZERO;
    r->a1 = FQ_ZERO;
}

static inline void fq2_set_one(fq2_t *r) {
    r->a0 = FQ_ONE;
    r->a1 = FQ_ZERO;
}

/* ---------------------------------------------------------------- Fq6 */

static inline void fq6_add(fq6_t *r, const fq6_t *a, const fq6_t *b) {
    fq2_add(&r->c[0], &a->c[0], &b->c[0]);
    fq2_add(&r->c[1], &a->c[1], &b->c[1]);
    fq2_add(&r->c[2], &a->c[2], &b->c[2]);
}

static inline void fq6_sub(fq6_t *r, const fq6_t *a, const fq6_t *b) {
    fq2_sub(&r->c[0], &a->c[0], &b->c[0]);
    fq2_sub(&r->c[1], &a->c[1], &b->c[1]);
    fq2_sub(&r->c[2], &a->c[2], &b->c[2]);
}

static inline void fq6_neg(fq6_t *r, const fq6_t *a) {
    fq2_neg(&r->c[0], &a->c[0]);
    fq2_neg(&r->c[1], &a->c[1]);
    fq2_neg(&r->c[2], &a->c[2]);
}

/* r = a * s = u a2 + a0 s + a1 s^2 */
static inline void fq6_mul_s(fq6_t *r, const fq6_t *a) {
    fq2_t t;
    fq2_mul_u(&t, &a->c[2]);
    r->c[2] = a->c[1];
    r->c[1] = a->c[0];
    r->c[0] = t;
}

/* Karatsuba: 6 Fq2 multiplications */
static inline void fq6_mul(fq6_t *r, const fq6_t *a, const fq6_t *b) {
    fq2_t v0, v1, v2, s, t, c0, c1, c2;
    fq2_mul(&v0, &a->c[0], &b->c[0]);
    fq2_mul(&v1, &a->c[1], &b->c[1]);
    fq2_mul(&v2, &a->c[2], &b->c[2]);

    fq2_add(&s, &a->c[1], &a->c[2]);
    fq2_add(&t, &b->c[1], &b->c[2]);
    fq2_mul(&c0, &s, &t);
    fq2_sub(&c0, &c0, &v1);
    fq2_sub(&c0, &c0, &v2);
    fq2_mul_u(&c0, &c0);
    fq2_add(&c0, &c0, &v0);

    fq2_add(&s, &a->c[0], &a->c[1]);
    fq2_add(&t, &b->c[0], &b->c[1]);
    fq2_mul(&c1, &s, &t);
    fq2_sub(&c1, &c1, &v0);
    fq2_sub(&c1, &c1, &v1);
    fq2_mul_u(&t, &v2);
    fq2_add(&c1, &c1, &t);

    fq2_add(&s, &a->c[0], &a->c[2]);
    fq2_add(&t, &b->c[0], &b->c[2]);
    fq2_mul(&c2, &s, &t);
    fq2_sub(&c2, &c2, &v0);
    fq2_sub(&c2, &c2, &v2);
    fq2_add(&c2, &c2, &v1);

    r->c[0] = c0;
    r->c[1] = c1;
    r->c[2] = c2;
}

/* r = a * (x + y s): 5 Fq2 multiplications */
static inline void fq6_mul_by_01(fq6_t *r, const fq6_t *a, const fq2_t *x, const fq2_t *y) {
    fq2_t v0, v1, s, t, c0, c1, c2;
    fq2_mul(&v0, &a->c[0], x);
    fq2_mul(&v1, &a->c[1], y);
    fq2_mul(&c0, &a->c[2], y);
    fq2_mul_u(&c0, &c0);
    fq2_add(&c0, &c0, &v0);
    fq2_add(&s, &a->c[0], &a->c[1]);
    fq2_add(&t, x, y);
    fq2_mul(&c1, &s, &t);
    fq2_sub(&c1, &c1, &v0);
    fq2_sub(&c1, &c1, &v1);
    fq2_mul(&c2, &a->c[2], x);
    fq2_add(&c2, &c2, &v1);
    r->c[0] = c0;
    r->c[1] = c1;
    r->c[2] = c2;
}

/* r = a * y s: 3 Fq2 multiplications */
static inline void fq6_mul_by_1(fq6_t *r, const fq6_t *a, const fq2_t *y) {
    fq2_t c0, c1, c2;
    fq2_mul(&c0, &a->c[2], y);
    fq2_mul_u(&c0, &c0);
    fq2_mul(&c1, &a->c[0], y);
    fq2_mul(&c2, &a->c[1], y);
    r->c[0] = c0;
    r->c[1] = c1;
    r->c[2] = c2;
}

static inline void fq6_inv(fq6_t *r, const fq6_t *a) {
    fq2_t t0, t1, t2, n, x;
    fq2_sqr(&t0, &a->c[0]);
    fq2_mul(&x, &a->c[1], &a->c[2]);
    fq2_mul_u(&x, &x);
    fq2_sub(&t0, &t0, &x);
    fq2_sqr(&t1, &a->c[2]);
    fq2_mul_u(&t1, &t1);
    fq2_mul(&x, &a->c[0], &a->c[1]);
    fq2_sub(&t1, &t1, &x);
    fq2_sqr(&t2, &a->c[1]);
    fq2_mul(&x, &a->c[0], &a->c[2]);
    fq2_sub(&t2, &t2, &x);
    fq2_mul(&n, &a->c[2], &t1);
    fq2_mul(&x, &a->c[1], &t2);
    fq2_add(&n, &n, &x);
    fq2_mul_u(&n, &n);
    fq2_mul(&x, &a->c[0], &t0);
    fq2_add(&n, &n, &x);
    fq2_inv(&n, &n);
    fq2_mul(&r->c[0], &t0, &n);
    fq2_mul(&r->c[1], &t1, &n);
    fq2_mul(&r->c[2], &t2, &n);
}

/* ---------------------------------------------------------------- Fq12 */

static inline void fq12_set_one(fq12_t *r) {
    memset(r, 0, sizeof(*r));
    r->c[0].c[0].a0 = FQ_ONE;
}

/* coefficient x_j of w^j */
static inline fq2_t *fq12_coef(fq12_t *f, int j) {
    return &f->c[j & 1].c[j >> 1];
}

static inline const fq2_t *fq12_coef_c(const fq12_t *f, int j) {
    return &f->c[j & 1].c[j >> 1];
}

static inline void fq12_mul(fq12_t *r, const fq12_t *a, const fq12_t *b) {
    fq6_t t0, t1, sa, sb;
    fq6_mul(&t0, &a->c[0], &b->c[0]);
    fq6_mul(&t1, &a->c[1], &b->c[1]);
    fq6_add(&sa, &a->c[0], &a->c[1]);
    fq6_add(&sb, &b->c[0], &b->c[1]);
    fq6_mul(&sa, &sa, &sb);
    fq6_sub(&sa, &sa, &t0);
    fq6_sub(&r->c[1], &sa, &t1);
    fq6_mul_s(&t1, &t1);
    fq6_add(&r->c[0], &t0, &t1);
}

/* (A + B w)^2 = (A + B)(A + B s) - AB - AB s + 2 AB w */
static inline void fq12_sqr(fq12_t *r, const fq12_t *a) {
    fq6_t t, s, bs;
    fq6_mul(&t, &a->c[0], &a->c[1]);
    fq6_add(&s, &a->c[0], &a->c[1]);
    fq6_mul_s(&bs, &a->c[1]);
    fq6_add(&bs, &bs, &a->c[0]);
    fq6_mul(&s, &s, &bs);
    fq6_sub(&s, &s, &t);
    fq6_mul_s(&bs, &t);
    fq6_sub(&r->c[0], &s, &bs);
    fq6_add(&r->c[1], &t, &t);
}

/*
 * f *= l for a Miller loop line l = c0 + c2 w^2 + c3 w^3, which is (c0 + c2 s) + (c3 s) w:
 * 13 Fq2 multiplications instead of 18.
 */
static inline void fq12_mul_line(fq12_t *f, const fq2_t *c0, const fq2_t *c2, const fq2_t *c3) {
    fq6_t t0, t1, s;
    fq2_t y;
    fq6_mul_by_01(&t0, &f->c[0], c0, c2);
    fq6_mul_by_1(&t1, &f->c[1], c3);
    fq6_add(&s, &f->c[0], &f->c[1]);
    fq2_add(&y, c2, c3);
    fq6_mul_by_01(&s, &s, c0, &y);
    fq6_sub(&s, &s, &t0);
    fq6_sub(&f->c[1], &s, &t1);
    fq6_mul_s(&t1, &t1);
    fq6_add(&f->c[0], &t0, &t1);
}

/* x^(q^6), which is the inverse for elements of the cyclotomic subgroup */
static inline void fq12_conj(fq12_t *r, const fq12_t *a) {
    r->c[0] = a->c[0];
    fq6_neg(&r->c[1], &a->c[1]);
}

static inline void fq12_inv(fq12_t *r, const fq12_t *a) {
    fq6_t t0, t1;
    fq6_mul(&t0, &a->c[0], &a->c[0]);
    fq6_mul(&t1, &a->c[1], &a->c[1]);
    fq6_mul_s(&t1, &t1);
    fq6_sub(&t0, &t0, &t1);
    fq6_inv(&t0, &t0);
    fq6_mul(&r->c[0], &a->c[0], &t0);
    fq6_mul(&r->c[1], &a->c[1], &t0);
    fq6_neg(&r->c[1], &r->c[1]);
}

static const fq_t SM9_FROB[3][6] = {SM9_FROB1_INIT, SM9_FROB2_INIT, SM9_FROB3_INIT};

/* r = a^(q^k), k in {1, 2, 3} */
static inline void fq12_frob(fq12_t *r, const fq12_t *a, int k) {
    int j;
    for (j = 0; j < 6; j++) {
        fq2_t c = *fq12_coef_c(a, j);
        if ((k & 1) != 0) {
            fq2_conj(&c, &c);
        }
        if (j != 0) {
            fq2_mul_fq(&c, &c, &SM9_FROB[k - 1][j]);
        }
        *fq12_coef(r, j) = c;
    }
}

/* (p0 + p1 v)^2 in Fq4 with v^2 = u */
static inline void fq4_sqr(fq2_t *r0, fq2_t *r1, const fq2_t *p0, const fq2_t *p1) {
    fq2_t t0, t1, s;
    fq2_sqr(&t0, p0);
    fq2_sqr(&t1, p1);
    fq2_add(&s, p0, p1);
    fq2_sqr(&s, &s);
    fq2_sub(&s, &s, &t0);
    fq2_sub(r1, &s, &t1);
    fq2_mul_u(&t1, &t1);
    fq2_add(r0, &t0, &t1);
}

/* r = 3 x - 2 y, and r = 3 x + 2 y */
static inline void fq2_3x_minus_2y(fq2_t *r, const fq2_t *x, const fq2_t *y) {
    fq2_t t;
    fq2_sub(&t, x, y);
    fq2_dbl(&t, &t);
    fq2_add(r, &t, x);
}

static inline void fq2_3x_plus_2y(fq2_t *r, const fq2_t *x, const fq2_t *y) {
    fq2_t t;
    fq2_add(&t, x, y);
    fq2_dbl(&t, &t);
    fq2_add(r, &t, x);
}

/*
 * Squaring in the cyclotomic subgroup (Granger and Scott). Writing f = a + b w + c w^2 over
 * Fq4, f^2 = (3a^2 - 2 conj(a)) + (3 v c^2 + 2 conj(b)) w + (3 b^2 - 2 conj(c)) w^2.
 */
static inline void fq12_cyclo_sqr(fq12_t *r, const fq12_t *f) {
    fq2_t a0 = f->c[0].c[0], a1 = f->c[1].c[1]; /* x0, x3 */
    fq2_t b0 = f->c[1].c[0], b1 = f->c[0].c[2]; /* x1, x4 */
    fq2_t c0 = f->c[0].c[1], c1 = f->c[1].c[2]; /* x2, x5 */
    fq2_t s0, s1, t;

    fq4_sqr(&s0, &s1, &a0, &a1);
    fq2_3x_minus_2y(&r->c[0].c[0], &s0, &a0);
    fq2_3x_plus_2y(&r->c[1].c[1], &s1, &a1);

    fq4_sqr(&s0, &s1, &b0, &b1);
    fq2_3x_minus_2y(&r->c[0].c[1], &s0, &c0);
    fq2_3x_plus_2y(&r->c[1].c[2], &s1, &c1);

    fq4_sqr(&s0, &s1, &c0, &c1);
    fq2_mul_u(&t, &s1);
    fq2_3x_plus_2y(&r->c[1].c[0], &t, &b0);
    fq2_3x_minus_2y(&r->c[0].c[2], &s0, &b1);
}

static inline void fq12_cmov(fq12_t *r, const fq12_t *a, uint64_t mask) {
    int i, j;
    for (i = 0; i < 2; i++) {
        for (j = 0; j < 3; j++) {
            fq2_cmov(&r->c[i].c[j], &a->c[i].c[j], mask);
        }
    }
}

static inline uint64_t fq12_equal(const fq12_t *a, const fq12_t *b) {
    uint64_t m = ~(uint64_t)0;
    int i, j;
    for (i = 0; i < 2; i++) {
        for (j = 0; j < 3; j++) {
            m &= fq2_equal(&a->c[i].c[j], &b->c[i].c[j]);
        }
    }
    return m;
}

/* 384 bytes: c2 || c1 || c0 over Fq4, each c_i = x_i + x_(i+3) v as x_(i+3) || x_i, Fq2 a1 || a0 */
static inline void fq12_to_bytes(uint8_t out[384], const fq12_t *f) {
    int i, k = 0;
    for (i = 2; i >= 0; i--) {
        const fq2_t *hi = fq12_coef_c(f, i + 3), *lo = fq12_coef_c(f, i);
        fq_to_bytes(out + 64 * k, &hi->a1);
        fq_to_bytes(out + 64 * k + 32, &hi->a0);
        fq_to_bytes(out + 64 * k + 64, &lo->a1);
        fq_to_bytes(out + 64 * k + 96, &lo->a0);
        k += 2;
    }
}

#endif /* SMX_SM9_TOWER_H */
