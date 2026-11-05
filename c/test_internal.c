/*
 * Randomized differential tests of the rewritten internals against slow
 * reference code in this file: bit-serial modular reduction and plain
 * square-and-multiply, sharing nothing with the production arithmetic.
 *
 * Reproducible: the PRNG seed is fixed, or taken from argv[1]. argv[2] scales the
 * number of iterations (default 1), which keeps sanitizer runs affordable.
 */
#include "sm2_ec.h"
#include "sm2_fn.h"
#include "smx_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed = 0, failed = 0;
static long scale = 1;

#define CHECK(name, cond)                                                                          \
    do {                                                                                           \
        if (cond) {                                                                                \
            passed++;                                                                              \
        } else {                                                                                   \
            failed++;                                                                              \
            if (failed < 30) {                                                                     \
                printf("  FAIL line %d: %s\n", __LINE__, name);                                    \
            }                                                                                      \
        }                                                                                          \
    } while (0)

/* ---- deterministic PRNG ---- */

static uint64_t rng_state = 0x9E3779B97F4A7C15ULL;

static uint64_t rng64(void) {
    uint64_t z = (rng_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

typedef struct {
    uint64_t v[4];
} U256;

static U256 rng_u256(void) {
    U256 r;
    int i;
    for (i = 0; i < 4; i++) {
        r.v[i] = rng64();
    }
    return r;
}

/* Values that force maximal carries, and long runs of 0 and 1 bits. */
static const uint64_t P_LIMBS[4] = {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL,
                                    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL};
static const uint64_t N_LIMBS[4] = {0x53BBF40939D54123ULL, 0x7203DF6B21C6052BULL,
                                    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL};

#define EDGE_COUNT 22
static U256 edge_value(int i) {
    static const U256 fixed[EDGE_COUNT] = {
        {{0, 0, 0, 0}},
        {{1, 0, 0, 0}},
        {{2, 0, 0, 0}},
        {{3, 0, 0, 0}},
        {{0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFFFFFFFFFFULL,
          0xFFFFFFFEFFFFFFFFULL}}, /* p-1 */
        {{0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFFFFFFFFFFULL,
          0xFFFFFFFEFFFFFFFFULL}},                                                  /* p */
        {{0, 0xFFFFFFFF00000001ULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL}}, /* p+1 */
        {{0x53BBF40939D54122ULL, 0x7203DF6B21C6052BULL, 0xFFFFFFFFFFFFFFFFULL,
          0xFFFFFFFEFFFFFFFFULL}}, /* n-1 */
        {{0x53BBF40939D54123ULL, 0x7203DF6B21C6052BULL, 0xFFFFFFFFFFFFFFFFULL,
          0xFFFFFFFEFFFFFFFFULL}}, /* n */
        {{0x53BBF40939D54124ULL, 0x7203DF6B21C6052BULL, 0xFFFFFFFFFFFFFFFFULL,
          0xFFFFFFFEFFFFFFFFULL}}, /* n+1 */
        {{~0ULL, ~0ULL, ~0ULL, ~0ULL}},
        {{~0ULL - 1, ~0ULL, ~0ULL, ~0ULL}},
        {{0, 0, 0, 1ULL << 63}},
        {{0, 0, 0, 0xFFFFFFFF00000000ULL}},
        {{0xFFFFFFFFULL, 0, 0, 0}},
        {{0xFFFFFFFF00000000ULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFF00000000ULL,
          0xFFFFFFFF00000000ULL}},
        {{0x00000000FFFFFFFFULL, 0x00000000FFFFFFFFULL, 0x00000000FFFFFFFFULL,
          0x00000000FFFFFFFFULL}},
        {{0, 0, ~0ULL, ~0ULL}},
        {{~0ULL, ~0ULL, 0, 0}},
        {{0x8000000080000000ULL, 0x8000000080000000ULL, 0x8000000080000000ULL,
          0x8000000080000000ULL}},
        {{0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL,
          0xFFFFFFFEFFFFFFFFULL}}, /* between p and 2^256 */
        {{0xAAAAAAAAAAAAAAAAULL, 0x5555555555555555ULL, 0xAAAAAAAAAAAAAAAAULL,
          0x5555555555555555ULL}},
    };
    return fixed[i];
}

/* ---- reference arithmetic: slow on purpose ---- */

static int ref_cmp(const uint64_t *a, const uint64_t *b, int n) {
    int i;
    for (i = n - 1; i >= 0; i--) {
        if (a[i] != b[i]) {
            return a[i] > b[i] ? 1 : -1;
        }
    }
    return 0;
}

static void ref_sub(uint64_t *r, const uint64_t *a, const uint64_t *b, int n) {
    uint64_t borrow = 0;
    int i;
    for (i = 0; i < n; i++) {
        uint64_t x = a[i], y = b[i];
        uint64_t d = x - y - borrow;
        borrow = (x < y) || (x == y && borrow) ? 1 : 0;
        r[i] = d;
    }
}

/* 32-bit digit schoolbook, deliberately not sharing the production multiplier. */
static void ref_mul_wide(uint64_t r[8], const uint64_t a[4], const uint64_t b[4]) {
    uint32_t x[8], y[8], z[16];
    int i, j;
    for (i = 0; i < 8; i++) {
        x[i] = (uint32_t)(a[i / 2] >> ((i & 1) * 32));
        y[i] = (uint32_t)(b[i / 2] >> ((i & 1) * 32));
    }
    memset(z, 0, sizeof(z));
    for (i = 0; i < 8; i++) {
        uint64_t c = 0;
        for (j = 0; j < 8; j++) {
            uint64_t t = (uint64_t)x[i] * y[j] + z[i + j] + c;
            z[i + j] = (uint32_t)t;
            c = t >> 32;
        }
        z[i + 8] = (uint32_t)c;
    }
    for (i = 0; i < 8; i++) {
        r[i] = (uint64_t)z[2 * i] | ((uint64_t)z[2 * i + 1] << 32);
    }
}

/* Shift-and-subtract remainder of a 512-bit value by a nonzero modulus. */
static void ref_mod_wide(uint64_t r[4], const uint64_t x[8], const uint64_t m[4]) {
    uint64_t rem[5] = {0, 0, 0, 0, 0}, mm[5];
    int i;
    memcpy(mm, m, 32);
    mm[4] = 0;
    for (i = 511; i >= 0; i--) {
        rem[4] = (rem[4] << 1) | (rem[3] >> 63);
        rem[3] = (rem[3] << 1) | (rem[2] >> 63);
        rem[2] = (rem[2] << 1) | (rem[1] >> 63);
        rem[1] = (rem[1] << 1) | (rem[0] >> 63);
        rem[0] = (rem[0] << 1) | ((x[i / 64] >> (i % 64)) & 1);
        if (ref_cmp(rem, mm, 5) >= 0) {
            ref_sub(rem, rem, mm, 5);
        }
    }
    memcpy(r, rem, 32);
}

static void ref_mulmod(uint64_t r[4], const uint64_t a[4], const uint64_t b[4],
                       const uint64_t m[4]) {
    uint64_t w[8];
    ref_mul_wide(w, a, b);
    ref_mod_wide(r, w, m);
}

static void ref_addmod(uint64_t r[4], const uint64_t a[4], const uint64_t b[4],
                       const uint64_t m[4]) {
    uint64_t w[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t carry = 0;
    int i;
    for (i = 0; i < 4; i++) {
        uint64_t s = a[i] + carry;
        uint64_t c1 = s < carry;
        uint64_t t = s + b[i];
        carry = c1 + (t < s);
        w[i] = t;
    }
    w[4] = carry;
    ref_mod_wide(r, w, m);
}

static void ref_submod(uint64_t r[4], const uint64_t a[4], const uint64_t b[4],
                       const uint64_t m[4]) {
    uint64_t neg[4];
    uint64_t rb[4];
    uint64_t w[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    memcpy(w, b, 32);
    ref_mod_wide(rb, w, m);
    ref_sub(neg, m, rb, 4);
    ref_addmod(r, a, neg, m);
}

/* a^e mod m, right to left. */
static void ref_powmod(uint64_t r[4], const uint64_t a[4], const uint64_t e[4],
                       const uint64_t m[4]) {
    uint64_t res[4] = {1, 0, 0, 0}, b[4];
    int i;
    memcpy(b, a, 32);
    for (i = 0; i < 256; i++) {
        if ((e[i / 64] >> (i % 64)) & 1) {
            ref_mulmod(res, res, b, m);
        }
        ref_mulmod(b, b, b, m);
    }
    memcpy(r, res, 32);
}

static void ref_reduce(uint64_t r[4], const uint64_t a[4], const uint64_t m[4]) {
    uint64_t w[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    memcpy(w, a, 32);
    ref_mod_wide(r, w, m);
}

/* ---- reference curve: affine, a = -3, every case spelled out ---- */

typedef struct {
    uint64_t x[4], y[4];
    int inf;
} RefPoint;

static const uint64_t TWO_LIMB[4] = {2, 0, 0, 0}, THREE_LIMB[4] = {3, 0, 0, 0};

static void ref_inv_p(uint64_t r[4], const uint64_t a[4]) {
    uint64_t e[4];
    ref_sub(e, P_LIMBS, TWO_LIMB, 4);
    ref_powmod(r, a, e, P_LIMBS);
}

static int is_zero4(const uint64_t a[4]) {
    return (a[0] | a[1] | a[2] | a[3]) == 0;
}

static RefPoint ref_add(const RefPoint *p, const RefPoint *q) {
    uint64_t lam[4], t[4], u[4];
    RefPoint r;
    r.inf = 0;
    if (p->inf) {
        return *q;
    }
    if (q->inf) {
        return *p;
    }
    if (ref_cmp(p->x, q->x, 4) == 0) {
        ref_addmod(t, p->y, q->y, P_LIMBS);
        if (is_zero4(t)) {
            memset(&r, 0, sizeof(r));
            r.inf = 1;
            return r;
        }
        ref_mulmod(t, p->x, p->x, P_LIMBS);
        ref_submod(t, t, (const uint64_t[4]){1, 0, 0, 0}, P_LIMBS);
        ref_mulmod(t, t, THREE_LIMB, P_LIMBS);
        ref_addmod(u, p->y, p->y, P_LIMBS);
    } else {
        ref_submod(t, q->y, p->y, P_LIMBS);
        ref_submod(u, q->x, p->x, P_LIMBS);
    }
    ref_inv_p(u, u);
    ref_mulmod(lam, t, u, P_LIMBS);
    ref_mulmod(t, lam, lam, P_LIMBS);
    ref_submod(t, t, p->x, P_LIMBS);
    ref_submod(r.x, t, q->x, P_LIMBS);
    ref_submod(t, p->x, r.x, P_LIMBS);
    ref_mulmod(t, t, lam, P_LIMBS);
    ref_submod(r.y, t, p->y, P_LIMBS);
    return r;
}

static RefPoint ref_generator(void) {
    RefPoint g;
    memcpy(g.x, EC_GX, 32);
    memcpy(g.y, EC_GY, 32);
    g.inf = 0;
    return g;
}

static RefPoint ref_negate(const RefPoint *p) {
    RefPoint r = *p;
    if (!p->inf && !is_zero4(p->y)) {
        ref_sub(r.y, P_LIMBS, p->y, 4);
    }
    return r;
}

/*
 * k*P with Jacobian-free double-and-add needs one inversion per step, which is far
 * too slow for scalar sweeps. This keeps the textbook projective form of doubling
 * and addition over reference field operations instead; it is only reached with
 * the reference field and handles the exceptional cases by testing for them.
 */
typedef struct {
    uint64_t x[4], y[4], z[4];
} RefJac;

static void ref_jac_double(RefJac *r, const RefJac *a) {
    uint64_t s[4], m[4], t[4], yy[4], u[4], x3[4], y3[4], z3[4];
    uint64_t zz[4];
    if (is_zero4(a->z) || is_zero4(a->y)) {
        memset(r, 0, sizeof(*r));
        r->x[0] = r->y[0] = 1;
        return;
    }
    ref_mulmod(yy, a->y, a->y, P_LIMBS);
    ref_mulmod(s, a->x, yy, P_LIMBS);
    ref_addmod(s, s, s, P_LIMBS);
    ref_addmod(s, s, s, P_LIMBS);
    ref_mulmod(zz, a->z, a->z, P_LIMBS);
    ref_submod(t, a->x, zz, P_LIMBS);
    ref_addmod(u, a->x, zz, P_LIMBS);
    ref_mulmod(m, t, u, P_LIMBS);
    ref_mulmod(m, m, THREE_LIMB, P_LIMBS);
    ref_mulmod(x3, m, m, P_LIMBS);
    ref_submod(x3, x3, s, P_LIMBS);
    ref_submod(x3, x3, s, P_LIMBS);
    ref_submod(t, s, x3, P_LIMBS);
    ref_mulmod(y3, m, t, P_LIMBS);
    ref_mulmod(t, yy, yy, P_LIMBS);
    ref_addmod(t, t, t, P_LIMBS);
    ref_addmod(t, t, t, P_LIMBS);
    ref_addmod(t, t, t, P_LIMBS);
    ref_submod(y3, y3, t, P_LIMBS);
    ref_mulmod(z3, a->y, a->z, P_LIMBS);
    ref_addmod(z3, z3, z3, P_LIMBS);
    memcpy(r->x, x3, 32);
    memcpy(r->y, y3, 32);
    memcpy(r->z, z3, 32);
}

static void ref_jac_add_affine(RefJac *r, const RefJac *a, const RefPoint *q) {
    uint64_t zz[4], u2[4], s2[4], h[4], rr[4], hh[4], hhh[4], v[4], t[4], x3[4], y3[4], z3[4];
    if (q->inf) {
        *r = *a;
        return;
    }
    if (is_zero4(a->z)) {
        memcpy(r->x, q->x, 32);
        memcpy(r->y, q->y, 32);
        memset(r->z, 0, 32);
        r->z[0] = 1;
        return;
    }
    ref_mulmod(zz, a->z, a->z, P_LIMBS);
    ref_mulmod(u2, q->x, zz, P_LIMBS);
    ref_mulmod(s2, q->y, a->z, P_LIMBS);
    ref_mulmod(s2, s2, zz, P_LIMBS);
    ref_submod(h, u2, a->x, P_LIMBS);
    ref_submod(rr, s2, a->y, P_LIMBS);
    if (is_zero4(h)) {
        if (is_zero4(rr)) {
            ref_jac_double(r, a);
        } else {
            memset(r, 0, sizeof(*r));
            r->x[0] = r->y[0] = 1;
        }
        return;
    }
    ref_mulmod(hh, h, h, P_LIMBS);
    ref_mulmod(hhh, hh, h, P_LIMBS);
    ref_mulmod(v, a->x, hh, P_LIMBS);
    ref_mulmod(x3, rr, rr, P_LIMBS);
    ref_submod(x3, x3, hhh, P_LIMBS);
    ref_submod(x3, x3, v, P_LIMBS);
    ref_submod(x3, x3, v, P_LIMBS);
    ref_submod(t, v, x3, P_LIMBS);
    ref_mulmod(y3, rr, t, P_LIMBS);
    ref_mulmod(t, a->y, hhh, P_LIMBS);
    ref_submod(y3, y3, t, P_LIMBS);
    ref_mulmod(z3, a->z, h, P_LIMBS);
    memcpy(r->x, x3, 32);
    memcpy(r->y, y3, 32);
    memcpy(r->z, z3, 32);
}

static RefPoint ref_from_jac(const RefJac *j) {
    RefPoint r;
    uint64_t zi[4], zi2[4], zi3[4];
    if (is_zero4(j->z)) {
        memset(&r, 0, sizeof(r));
        r.inf = 1;
        return r;
    }
    ref_inv_p(zi, j->z);
    ref_mulmod(zi2, zi, zi, P_LIMBS);
    ref_mulmod(zi3, zi2, zi, P_LIMBS);
    ref_mulmod(r.x, j->x, zi2, P_LIMBS);
    ref_mulmod(r.y, j->y, zi3, P_LIMBS);
    r.inf = 0;
    return r;
}

/* Plain binary double-and-add over the full 256 bits; no scalar reduction. */
static RefPoint ref_mul(const RefPoint *p, const uint64_t k[4]) {
    RefJac acc;
    int i;
    memset(&acc, 0, sizeof(acc));
    acc.x[0] = acc.y[0] = 1;
    for (i = 255; i >= 0; i--) {
        ref_jac_double(&acc, &acc);
        if ((k[i / 64] >> (i % 64)) & 1) {
            ref_jac_add_affine(&acc, &acc, p);
        }
    }
    return ref_from_jac(&acc);
}

/* ---- production values to reference form ---- */

static RefPoint from_prod(const Jac *j) {
    RefJac rj;
    memcpy(rj.x, j->x, 32);
    memcpy(rj.y, j->y, 32);
    memcpy(rj.z, j->z, 32);
    return ref_from_jac(&rj);
}

static int points_equal(const RefPoint *a, const RefPoint *b) {
    if (a->inf || b->inf) {
        return a->inf && b->inf;
    }
    return ref_cmp(a->x, b->x, 4) == 0 && ref_cmp(a->y, b->y, 4) == 0;
}

static void to_jac(Jac *j, const RefPoint *p) {
    if (p->inf) {
        jac_set_infinity(j);
    } else {
        jac_set_affine(j, p->x, p->y);
    }
}

/* A random Jacobian representative of p, so Z != 1 paths are exercised. */
static void to_jac_random_z(Jac *j, const RefPoint *p) {
    U256 zr;
    Fe z2, z3;
    to_jac(j, p);
    if (p->inf) {
        return;
    }
    zr = rng_u256();
    ref_reduce(zr.v, zr.v, P_LIMBS);
    if (is_zero4(zr.v)) {
        zr.v[0] = 1;
    }
    ref_mulmod(z2, zr.v, zr.v, P_LIMBS);
    ref_mulmod(z3, z2, zr.v, P_LIMBS);
    ref_mulmod(j->x, p->x, z2, P_LIMBS);
    ref_mulmod(j->y, p->y, z3, P_LIMBS);
    memcpy(j->z, zr.v, 32);
}

/* ---- field tests ---- */

static void check_fe_pair(const uint64_t a[4], const uint64_t b[4]) {
    Fe r, want;
    uint64_t ra[4], rb[4];

    /* mul and sqr take any 256-bit input */
    fe_mul(r, a, b);
    ref_mulmod(want, a, b, P_LIMBS);
    CHECK("fe_mul", ref_cmp(r, want, 4) == 0);
    fe_sqr(r, a);
    ref_mulmod(want, a, a, P_LIMBS);
    CHECK("fe_sqr", ref_cmp(r, want, 4) == 0);

    /* aliasing */
    memcpy(r, a, 32);
    fe_mul(r, r, b);
    ref_mulmod(want, a, b, P_LIMBS);
    CHECK("fe_mul aliased", ref_cmp(r, want, 4) == 0);

    /* add, sub, neg require reduced input */
    ref_reduce(ra, a, P_LIMBS);
    ref_reduce(rb, b, P_LIMBS);
    fe_add(r, ra, rb);
    ref_addmod(want, ra, rb, P_LIMBS);
    CHECK("fe_add", ref_cmp(r, want, 4) == 0);
    fe_sub(r, ra, rb);
    ref_submod(want, ra, rb, P_LIMBS);
    CHECK("fe_sub", ref_cmp(r, want, 4) == 0);
    fe_cond_neg(r, ra, ~(uint64_t)0);
    ref_submod(want, (const uint64_t[4]){0, 0, 0, 0}, ra, P_LIMBS);
    CHECK("fe_cond_neg set", ref_cmp(r, want, 4) == 0);
    fe_cond_neg(r, ra, 0);
    CHECK("fe_cond_neg clear", ref_cmp(r, ra, 4) == 0);

    {
        static const uint64_t small[] = {2, 3, 4, 8, 16};
        size_t i;
        for (i = 0; i < sizeof(small) / sizeof(small[0]); i++) {
            uint64_t m[4] = {0, 0, 0, 0};
            m[0] = small[i];
            fe_mul_small(r, ra, small[i]);
            ref_mulmod(want, ra, m, P_LIMBS);
            CHECK("fe_mul_small", ref_cmp(r, want, 4) == 0);
        }
    }

    CHECK("fe_equal", (fe_equal(ra, rb) != 0) == (ref_cmp(ra, rb, 4) == 0));
    CHECK("fe_is_zero", (fe_is_zero(ra) != 0) == is_zero4(ra));
}

static void test_field(void) {
    long i;
    int x, y;
    printf("field arithmetic\n");
    for (x = 0; x < EDGE_COUNT; x++) {
        for (y = 0; y < EDGE_COUNT; y++) {
            U256 a = edge_value(x), b = edge_value(y);
            check_fe_pair(a.v, b.v);
        }
    }
    for (i = 0; i < 2000 * scale; i++) {
        U256 a = rng_u256(), b = rng_u256();
        check_fe_pair(a.v, b.v);
    }

    /* the wide reduction on inputs no product of reduced values would produce */
    for (i = 0; i < 2000 * scale; i++) {
        uint64_t w[8], w2[8], r[4], want[4];
        int j;
        for (j = 0; j < 8; j++) {
            uint64_t pick = rng64() % 4;
            w[j] = pick == 0 ? 0 : pick == 1 ? ~(uint64_t)0 : rng64();
        }
        memcpy(w2, w, sizeof(w));
        fe_reduce_wide(r, w2);
        ref_mod_wide(want, w, P_LIMBS);
        CHECK("fe_reduce_wide", ref_cmp(r, want, 4) == 0);
    }

    for (x = 0; x < EDGE_COUNT; x++) {
        U256 a = edge_value(x);
        Fe r;
        uint64_t e[4], want[4];
        ref_sub(e, P_LIMBS, TWO_LIMB, 4);
        fe_inv(r, a.v);
        ref_powmod(want, a.v, e, P_LIMBS);
        CHECK("fe_inv edge", ref_cmp(r, want, 4) == 0);
    }
    for (i = 0; i < 20 * scale; i++) {
        U256 a = rng_u256();
        Fe r, product;
        uint64_t e[4], want[4];
        ref_sub(e, P_LIMBS, TWO_LIMB, 4);
        fe_inv(r, a.v);
        ref_powmod(want, a.v, e, P_LIMBS);
        CHECK("fe_inv", ref_cmp(r, want, 4) == 0);
        fe_mul(product, r, a.v);
        CHECK("a * 1/a", is_zero4(a.v) || ref_cmp(product, FE_ONE, 4) == 0);
    }
}

/* ---- order arithmetic ---- */

static void check_fn_pair(const uint64_t a[4], const uint64_t b[4]) {
    uint64_t r[4], want[4];
    fn_mul(r, a, b);
    ref_mulmod(want, a, b, N_LIMBS);
    CHECK("fn_mul", ref_cmp(r, want, 4) == 0);
    fn_reduce(r, a);
    ref_reduce(want, a, N_LIMBS);
    CHECK("fn_reduce", ref_cmp(r, want, 4) == 0);
}

static void test_order(void) {
    long i;
    int x, y;
    uint64_t e[4];
    printf("order arithmetic\n");
    for (x = 0; x < EDGE_COUNT; x++) {
        for (y = 0; y < EDGE_COUNT; y++) {
            U256 a = edge_value(x), b = edge_value(y);
            check_fn_pair(a.v, b.v);
        }
    }
    for (i = 0; i < 2000 * scale; i++) {
        U256 a = rng_u256(), b = rng_u256();
        check_fn_pair(a.v, b.v);
    }
    ref_sub(e, N_LIMBS, TWO_LIMB, 4);
    for (x = 0; x < EDGE_COUNT; x++) {
        U256 a = edge_value(x);
        uint64_t r[4], want[4];
        fn_inv(r, a.v);
        ref_powmod(want, a.v, e, N_LIMBS);
        CHECK("fn_inv edge", ref_cmp(r, want, 4) == 0);
    }
    for (i = 0; i < 20 * scale; i++) {
        U256 a = rng_u256();
        uint64_t r[4], want[4];
        fn_inv(r, a.v);
        ref_powmod(want, a.v, e, N_LIMBS);
        CHECK("fn_inv", ref_cmp(r, want, 4) == 0);
    }
}

/* ---- public generic BigInt256 ---- */

static BigInt256 to_big(const uint64_t v[4]) {
    BigInt256 r;
    memcpy(r.limbs, v, 32);
    return r;
}

/* Moduli chosen to hit the corners of Knuth D, including the add-back branch. */
static U256 interesting_modulus(void) {
    U256 m;
    int kind = (int)(rng64() % 8);
    int shift;
    m = rng_u256();
    switch (kind) {
    case 0: /* divisor top digit is the normalization boundary */
        m.v[3] = 0x8000000000000000ULL;
        m.v[2] = m.v[1] = 0;
        break;
    case 1:
        m.v[3] = 0x80000000FFFFFFFFULL;
        m.v[2] = ~(uint64_t)0;
        break;
    case 2:
        m.v[3] = 0;
        m.v[2] = (rng64() >> 32) | 0x80000000u;
        break;
    case 3:
        m.v[3] = 0;
        m.v[2] = 0;
        m.v[1] = 1;
        break;
    case 4:
        m.v[3] = m.v[2] = m.v[1] = 0;
        m.v[0] = (rng64() >> 32) | 1;
        break;
    case 5:
        m.v[3] = m.v[2] = m.v[1] = 0;
        m.v[0] |= 1;
        break;
    case 6:
        shift = (int)(rng64() % 64);
        m.v[3] >>= shift;
        break;
    default:
        break;
    }
    if (is_zero4(m.v)) {
        m.v[0] = 3;
    }
    return m;
}

static U256 interesting_operand(void) {
    U256 a = rng_u256();
    switch (rng64() % 5) {
    case 0:
        a.v[0] = a.v[1] = 0;
        break;
    case 1:
        a.v[2] = a.v[3] = ~(uint64_t)0;
        break;
    case 2:
        a.v[0] &= 0xFFFFFFFF00000000ULL;
        a.v[1] &= 0xFFFFFFFF00000000ULL;
        break;
    default:
        break;
    }
    return a;
}

static void test_generic(void) {
    long i;
    printf("generic bigint\n");
    for (i = 0; i < 20000 * scale; i++) {
        U256 a = interesting_operand(), b = interesting_operand(), m = interesting_modulus();
        BigInt256 ba = to_big(a.v), bb = to_big(b.v), bm = to_big(m.v), r;
        uint64_t want[4], wide[8], wide_want[8];

        bigint256_mod_mul(&r, &ba, &bb, &bm);
        ref_mulmod(want, a.v, b.v, m.v);
        CHECK("bigint256_mod_mul", ref_cmp(r.limbs, want, 4) == 0);

        bigint256_mul(wide, &ba, &bb);
        ref_mul_wide(wide_want, a.v, b.v);
        CHECK("bigint256_mul", ref_cmp(wide, wide_want, 8) == 0);

        CHECK("bigint256_compare", bigint256_compare(&ba, &bb) == ref_cmp(a.v, b.v, 4));
        CHECK("bigint256_compare equal", bigint256_compare(&ba, &ba) == 0);
    }
    for (i = 0; i < 200 * scale; i++) {
        U256 a = rng_u256(), e = rng_u256(), m = interesting_modulus();
        BigInt256 ba = to_big(a.v), be, bm = to_big(m.v), r;
        uint64_t want[4];
        int bits = (int)(rng64() % 257);
        int j;
        for (j = 0; j < 4; j++) {
            if (bits <= 64 * j) {
                e.v[j] = 0;
            } else if (bits < 64 * (j + 1)) {
                e.v[j] &= ((uint64_t)1 << (bits - 64 * j)) - 1;
            }
        }
        be = to_big(e.v);
        bigint256_mod_pow(&r, &ba, &be, &bm);
        if (is_zero4(e.v)) {
            CHECK("mod_pow exponent 0",
                  bigint256_is_one(&bm) ? bigint256_is_zero(&r) : bigint256_is_one(&r));
        } else {
            ref_powmod(want, a.v, e.v, m.v);
            CHECK("bigint256_mod_pow", ref_cmp(r.limbs, want, 4) == 0);
        }
    }
    /*
     * Digits at the extremes of base 2^32 make the quotient estimate too large
     * often enough to reach Knuth's add-back step, which random values practically
     * never do. The first case is the classic example from Hacker's Delight.
     */
    {
        static const uint32_t extreme[] = {
            0, 1, 2, 3, 0x7FFFFFFFu, 0x80000000u, 0x80000001u, 0xFFFFFFFEu, 0xFFFFFFFFu};
        BigInt256 ba = {{0xFFFFFFFE00000000ULL, 0x80000000ULL, 0, 0}};
        BigInt256 bm = {{0x80000000FFFFFFFFULL, 0, 0, 0}};
        BigInt256 bone = bigint256_one(), r;
        uint64_t want[4];
        bigint256_mod_mul(&r, &ba, &bone, &bm);
        ref_mulmod(want, ba.limbs, bone.limbs, bm.limbs);
        CHECK("Knuth add-back example", ref_cmp(r.limbs, want, 4) == 0);

        for (i = 0; i < 100000 * scale; i++) {
            uint32_t ad[8], md[8];
            int j, md_len = 2 + (int)(rng64() % 7);
            for (j = 0; j < 8; j++) {
                ad[j] = extreme[rng64() % 9];
                md[j] = j < md_len ? extreme[rng64() % 9] : 0;
            }
            for (j = 0; j < 4; j++) {
                ba.limbs[j] = (uint64_t)ad[j * 2] | ((uint64_t)ad[j * 2 + 1] << 32);
                bm.limbs[j] = (uint64_t)md[j * 2] | ((uint64_t)md[j * 2 + 1] << 32);
            }
            if (bigint256_is_zero(&bm)) {
                continue;
            }
            bigint256_mod_mul(&r, &ba, &bone, &bm);
            ref_mulmod(want, ba.limbs, bone.limbs, bm.limbs);
            CHECK("Knuth extreme digits", ref_cmp(r.limbs, want, 4) == 0);
        }
    }
    /* inverses, against the definition: a * r = 1 mod m, or 0 only when none exists */
    for (i = 0; i < 2000 * scale; i++) {
        U256 a = interesting_operand(), m = interesting_modulus();
        BigInt256 ba = to_big(a.v), bm = to_big(m.v), r, check, one = bigint256_one();
        bigint256_mod_inverse(&r, &ba, &bm);
        if (bigint256_is_one(&bm)) {
            CHECK("inverse mod 1", bigint256_is_zero(&r));
        } else if (bigint256_is_zero(&r)) {
            /* no inverse: gcd > 1, shown by a shared factor or a zero residue */
            uint64_t x[4], y[4];
            ref_reduce(x, a.v, m.v);
            memcpy(y, m.v, 32);
            while (!is_zero4(x)) {
                uint64_t t[4];
                ref_reduce(t, y, x);
                memcpy(y, x, 32);
                memcpy(x, t, 32);
            }
            CHECK("zero means no inverse", ref_cmp(y, one.limbs, 4) != 0);
        } else {
            bigint256_mod_mul(&check, &ba, &r, &bm);
            CHECK("a * inverse = 1", bigint256_is_one(&check));
            CHECK("inverse is reduced", bigint256_compare(&r, &bm) < 0);
        }
    }
    {
        BigInt256 a = {{5, 0, 0, 0}}, b = {{7, 0, 0, 0}}, zero = {{0, 0, 0, 0}}, r;
        bigint256_mod_mul(&r, &a, &b, &zero);
        CHECK("mod_mul by zero modulus is zero", bigint256_is_zero(&r));
    }
}

/* ---- hex ---- */

static unsigned ref_nibble(unsigned char c) {
    if (c >= '0' && c <= '9') {
        return c - (unsigned)'0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - (unsigned)'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - (unsigned)'A' + 10;
    }
    return 0;
}

static int ref_is_hex(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static void test_hex(void) {
    static const char lower[] = "0123456789abcdef", upper[] = "0123456789ABCDEF";
    uint8_t data[100], back[100];
    char text[201], want[201];
    int v, pos;
    size_t len;
    printf("hex\n");

    /* every byte value in every SIMD lane position, and in the scalar tail */
    for (len = 0; len <= 100; len++) {
        for (v = 0; v < 256; v += (len < 34 ? 1 : 37)) {
            size_t i;
            for (i = 0; i < len; i++) {
                data[i] = (uint8_t)(v + (int)i * 7);
                want[i * 2] = lower[data[i] >> 4];
                want[i * 2 + 1] = lower[data[i] & 15];
            }
            want[len * 2] = '\0';
            memset(text, 0x55, sizeof(text));
            bytes_to_hex(data, len, text);
            CHECK("bytes_to_hex", strcmp(text, want) == 0);
            CHECK("bytes_to_hex no overrun", len == 100 || text[len * 2 + 1] == 0x55);
            for (i = 0; i < len; i++) {
                want[i * 2] = upper[data[i] >> 4];
                want[i * 2 + 1] = upper[data[i] & 15];
            }
            smx_hex_encode(data, len, text, 'A');
            CHECK("hex upper", memcmp(text, want, len * 2) == 0);
            memset(back, 0, sizeof(back));
            CHECK("hex_to_bytes length", hex_to_bytes(want, back, sizeof(back)) == (int)len);
            CHECK("hex_to_bytes", memcmp(back, data, len) == 0);
        }
    }

    /* every character at every position, including non-hex: those decode as 0 */
    for (pos = 0; pos < 64; pos++) {
        for (v = 1; v < 256; v++) {
            uint8_t got[32], expect[32];
            char s[65];
            int i;
            memset(s, 'c', 64);
            s[pos] = (char)v;
            s[64] = '\0';
            for (i = 0; i < 32; i++) {
                expect[i] = (uint8_t)((ref_nibble((unsigned char)s[i * 2]) << 4) |
                                      ref_nibble((unsigned char)s[i * 2 + 1]));
            }
            CHECK("hex decode validity",
                  smx_hex_decode(s, 32, got) == ref_is_hex((unsigned char)v));
            CHECK("hex decode char", memcmp(got, expect, 32) == 0);
        }
    }
    CHECK("hex_to_bytes too long", hex_to_bytes("0011", back, 1) == -1);
    CHECK("hex_to_bytes rejects 0x prefix", hex_to_bytes("0xAB", back, 1) == -1);
    CHECK("hex_to_bytes rejects odd length", hex_to_bytes("ABC", back, 2) == -1);
    CHECK("hex_to_bytes rejects non-hex", hex_to_bytes("zz", back, 1) == -1);
    CHECK("lowercase decoder takes lowercase", smx_hex_decode_lower("ab09", 2, back) == 1);
    CHECK("lowercase decoder refuses A", smx_hex_decode_lower("Ab09", 2, back) == 0);
    {
        /* both lane position and the scalar tail, and the SIMD path */
        char text_lower[67];
        int p2;
        memset(text_lower, 'c', 66);
        text_lower[66] = '\0';
        CHECK("lowercase 33 bytes", smx_hex_decode_lower(text_lower, 33, data) == 1);
        for (p2 = 0; p2 < 66; p2++) {
            text_lower[p2] = 'C';
            CHECK("uppercase anywhere", smx_hex_decode_lower(text_lower, 33, data) == 0);
            CHECK("either case decoder", smx_hex_decode(text_lower, 33, data) == 1);
            text_lower[p2] = 'c';
        }
    }
}

/* ---- group ---- */

static RefPoint random_point(void) {
    U256 k = rng_u256();
    RefPoint g = ref_generator();
    Jac j;
    RefPoint p;
    /* one reference multiple per test point; production k*G is checked separately */
    k.v[3] &= 0x0000FFFFFFFFFFFFULL;
    p = ref_mul(&g, k.v);
    to_jac(&j, &p);
    return p;
}

static void test_tables(void) {
    RefPoint base = ref_generator();
    RefPoint g = ref_generator(), twice, cur;
    int i, j;
    printf("precomputed tables\n");
    for (i = 0; i < SMX_COMB_WINDOWS; i++) {
        cur = base;
        for (j = 0; j < SMX_COMB_ENTRIES; j++) {
            CHECK("comb x", memcmp(sm2_comb[i][j], cur.x, 32) == 0);
            CHECK("comb y", memcmp(sm2_comb[i][j] + 4, cur.y, 32) == 0);
            if (j + 1 < SMX_COMB_ENTRIES) {
                cur = ref_add(&cur, &base);
            }
        }
        for (j = 0; j < SMX_COMB_BITS; j++) {
            base = ref_add(&base, &base);
        }
    }
    twice = ref_add(&g, &g);
    cur = g;
    for (j = 0; j < SMX_NAF_G_ENTRIES; j++) {
        CHECK("naf x", memcmp(sm2_naf_g[j], cur.x, 32) == 0);
        CHECK("naf y", memcmp(sm2_naf_g[j] + 4, cur.y, 32) == 0);
        if (j + 1 < SMX_NAF_G_ENTRIES) {
            cur = ref_add(&cur, &twice);
        }
    }
}

static void test_point_ops(void) {
    long i;
    RefPoint inf;
    Jac jinf;
    printf("point operations\n");
    memset(&inf, 0, sizeof(inf));
    inf.inf = 1;
    jac_set_infinity(&jinf);

    for (i = 0; i < 12 * scale; i++) {
        RefPoint p = random_point(), q = random_point();
        RefPoint neg = ref_negate(&p), want, got;
        Jac jp, jq, r;
        uint64_t same;

        to_jac_random_z(&jp, &p);
        to_jac_random_z(&jq, &q);

        /* distinct points */
        want = ref_add(&p, &q);
        same = jac_add(&r, &jp, &jq);
        got = from_prod(&r);
        CHECK("jac_add", !same && points_equal(&got, &want));
        same = jac_add_affine(&r, &jp, q.x, q.y, ~(uint64_t)0);
        got = from_prod(&r);
        CHECK("jac_add_affine", !same && points_equal(&got, &want));

        /* doubling */
        want = ref_add(&p, &p);
        jac_double(&r, &jp);
        got = from_prod(&r);
        CHECK("jac_double", points_equal(&got, &want));

        /* P + P */
        to_jac_random_z(&jq, &p);
        same = jac_add(&r, &jp, &jq);
        CHECK("jac_add reports P + P", same != 0);
        jac_add_complete(&r, &jp, &jq);
        got = from_prod(&r);
        CHECK("jac_add_complete P + P", points_equal(&got, &want));
        jac_add_vt(&r, &jp, &jq);
        got = from_prod(&r);
        CHECK("jac_add_vt P + P", points_equal(&got, &want));
        same = jac_add_affine(&r, &jp, p.x, p.y, ~(uint64_t)0);
        CHECK("jac_add_affine reports P + P", same != 0);

        /* P + (-P) */
        to_jac_random_z(&jq, &neg);
        same = jac_add(&r, &jp, &jq);
        got = from_prod(&r);
        CHECK("jac_add P + (-P)", !same && got.inf);
        same = jac_add_affine(&r, &jp, neg.x, neg.y, ~(uint64_t)0);
        got = from_prod(&r);
        CHECK("jac_add_affine P + (-P)", !same && got.inf);

        /* infinity on each side, and on both */
        same = jac_add(&r, &jp, &jinf);
        got = from_prod(&r);
        CHECK("jac_add P + inf", !same && points_equal(&got, &p));
        same = jac_add(&r, &jinf, &jp);
        got = from_prod(&r);
        CHECK("jac_add inf + P", !same && points_equal(&got, &p));
        same = jac_add(&r, &jinf, &jinf);
        got = from_prod(&r);
        CHECK("jac_add inf + inf", !same && got.inf);
        same = jac_add_affine(&r, &jinf, p.x, p.y, ~(uint64_t)0);
        got = from_prod(&r);
        CHECK("jac_add_affine inf + P", !same && points_equal(&got, &p));
        same = jac_add_affine(&r, &jp, q.x, q.y, 0);
        got = from_prod(&r);
        CHECK("jac_add_affine P + inf", !same && points_equal(&got, &p));
        same = jac_add_affine(&r, &jinf, q.x, q.y, 0);
        got = from_prod(&r);
        CHECK("jac_add_affine inf + inf", !same && got.inf);
        jac_double(&r, &jinf);
        got = from_prod(&r);
        CHECK("jac_double inf", got.inf);
    }
}

/* Every digit decomposition must sum back to k; compared as big integers mod 2^320. */
static void test_recodings(void) {
    long i;
    printf("scalar recodings\n");
    for (i = 0; i < 3000 * scale; i++) {
        U256 k = i < EDGE_COUNT ? edge_value((int)i) : interesting_operand();
        int8_t naf[257];
        int width;
        for (width = 5; width <= 8; width += 3) {
            int len = ec_wnaf(naf, k.v, width);
            uint64_t sum[5] = {0, 0, 0, 0, 0};
            int j, ok = 1;
            int last_nonzero = -width;
            for (j = len - 1; j >= 0; j--) {
                uint64_t c;
                int d = naf[j];
                int l;
                c = sum[4] >> 63;
                (void)c;
                for (l = 4; l > 0; l--) {
                    sum[l] = (sum[l] << 1) | (sum[l - 1] >> 63);
                }
                sum[0] <<= 1;
                if (d > 0) {
                    uint64_t carry;
                    sum[0] = smx_addc(sum[0], (uint64_t)d, 0, &carry);
                    for (l = 1; l < 5; l++) {
                        sum[l] = smx_addc(sum[l], 0, carry, &carry);
                    }
                } else if (d < 0) {
                    uint64_t borrow;
                    sum[0] = smx_subb(sum[0], (uint64_t)(-d), 0, &borrow);
                    for (l = 1; l < 5; l++) {
                        sum[l] = smx_subb(sum[l], 0, borrow, &borrow);
                    }
                }
            }
            for (j = 0; j < len; j++) {
                if (naf[j] != 0) {
                    int d = naf[j] < 0 ? -naf[j] : naf[j];
                    if ((d & 1) == 0 || d >= (1 << (width - 1))) {
                        ok = 0;
                    }
                    if (j - last_nonzero < width && last_nonzero >= 0) {
                        ok = 0;
                    }
                    last_nonzero = j;
                }
            }
            CHECK("wNAF digit shape", ok);
            CHECK("wNAF sums to k", memcmp(sum, k.v, 32) == 0 && sum[4] == 0);
        }

        {
            uint64_t sum[5] = {0, 0, 0, 0, 0};
            int w;
            for (w = EC_VAR_WINDOWS - 1; w >= 0; w--) {
                uint64_t negative, carry;
                unsigned mag = ec_booth_digit(k.v, EC_VAR_BITS, w, &negative);
                int l, s;
                CHECK("Booth magnitude", mag <= (unsigned)EC_VAR_ENTRIES);
                for (s = 0; s < EC_VAR_BITS; s++) {
                    for (l = 4; l > 0; l--) {
                        sum[l] = (sum[l] << 1) | (sum[l - 1] >> 63);
                    }
                    sum[0] <<= 1;
                }
                if (negative) {
                    sum[0] = smx_subb(sum[0], mag, 0, &carry);
                    for (l = 1; l < 5; l++) {
                        sum[l] = smx_subb(sum[l], 0, carry, &carry);
                    }
                } else {
                    sum[0] = smx_addc(sum[0], mag, 0, &carry);
                    for (l = 1; l < 5; l++) {
                        sum[l] = smx_addc(sum[l], 0, carry, &carry);
                    }
                }
            }
            CHECK("Booth sums to k", memcmp(sum, k.v, 32) == 0 && sum[4] == 0);
        }
    }
}

static void add_small(uint64_t r[4], const uint64_t a[4], uint64_t d) {
    uint64_t c;
    r[0] = smx_addc(a[0], d, 0, &c);
    r[1] = smx_addc(a[1], 0, c, &c);
    r[2] = smx_addc(a[2], 0, c, &c);
    r[3] = smx_addc(a[3], 0, c, &c);
}

static void sub_small(uint64_t r[4], const uint64_t a[4], uint64_t d) {
    uint64_t c;
    r[0] = smx_subb(a[0], d, 0, &c);
    r[1] = smx_subb(a[1], 0, c, &c);
    r[2] = smx_subb(a[2], 0, c, &c);
    r[3] = smx_subb(a[3], 0, c, &c);
}

static void check_all_mults(const char *what, const uint64_t k[4], const RefPoint *p,
                            const RefPoint *want_p, const RefPoint *want_g) {
    Jac base, r;
    RefPoint got;
    (void)what;
    to_jac_random_z(&base, p);
    ec_mul_ct(&r, &base, k);
    got = from_prod(&r);
    CHECK("ec_mul_ct", points_equal(&got, want_p));
    ec_mul_vt(&r, &base, k);
    got = from_prod(&r);
    CHECK("ec_mul_vt", points_equal(&got, want_p));
    ec_mul_g(&r, k);
    got = from_prod(&r);
    CHECK("ec_mul_g", points_equal(&got, want_g));
}

static void test_scalar_mult(void) {
    RefPoint g = ref_generator();
    RefPoint p = random_point();
    uint64_t k[4];
    long i;
    int j;
    printf("scalar multiplication\n");

    /* k = 0..80 */
    {
        RefPoint mp, mg;
        memset(&mp, 0, sizeof(mp));
        mp.inf = 1;
        mg = mp;
        memset(k, 0, sizeof(k));
        for (j = 0; j <= 80; j++) {
            k[0] = (uint64_t)j;
            check_all_mults("small", k, &p, &mp, &mg);
            mp = ref_add(&mp, &p);
            mg = ref_add(&mg, &g);
        }
    }

    /* k = n - j and n + j, which include the P == Q cases in the ladder */
    {
        RefPoint mp, mg;
        memset(&mp, 0, sizeof(mp));
        mp.inf = 1;
        mg = mp;
        for (j = 0; j <= 80; j++) {
            RefPoint np = ref_negate(&mp), ng = ref_negate(&mg);
            sub_small(k, N_LIMBS, (uint64_t)j);
            check_all_mults("n - j", k, &p, &np, &ng);
            add_small(k, N_LIMBS, (uint64_t)j);
            check_all_mults("n + j", k, &p, &mp, &mg);
            mp = ref_add(&mp, &p);
            mg = ref_add(&mg, &g);
        }
    }

    /* single bits and full reference multiplications */
    for (j = 0; j < 256; j += (scale > 1 ? 1 : 5)) {
        RefPoint wp, wg;
        memset(k, 0, sizeof(k));
        k[j / 64] = (uint64_t)1 << (j % 64);
        wp = ref_mul(&p, k);
        wg = ref_mul(&g, k);
        check_all_mults("power of two", k, &p, &wp, &wg);
    }
    for (j = 0; j < EDGE_COUNT; j++) {
        U256 e = edge_value(j);
        RefPoint wp = ref_mul(&p, e.v), wg = ref_mul(&g, e.v);
        check_all_mults("edge", e.v, &p, &wp, &wg);
    }
    for (i = 0; i < 30 * scale; i++) {
        U256 a = interesting_operand();
        RefPoint q = i % 4 == 0 ? g : p;
        RefPoint wp = ref_mul(&q, a.v), wg = ref_mul(&g, a.v);
        check_all_mults("random", a.v, &q, &wp, &wg);
    }
}

static void test_double_mult(void) {
    RefPoint g = ref_generator();
    RefPoint p = random_point();
    Jac base, r;
    long i;
    printf("double scalar multiplication\n");
    to_jac_random_z(&base, &p);
    for (i = 0; i < 30 * scale; i++) {
        U256 s = i < EDGE_COUNT ? edge_value((int)i) : rng_u256();
        U256 t = rng_u256();
        RefPoint a = ref_mul(&g, s.v), b = ref_mul(&p, t.v), want = ref_add(&a, &b), got;
        ec_double_mul_vt(&r, s.v, t.v, &base);
        got = from_prod(&r);
        CHECK("ec_double_mul_vt", points_equal(&got, &want));
    }
    /* s*G + t*G: forces P == Q and P == -Q inside the interleaving */
    jac_set_affine(&base, g.x, g.y);
    for (i = 0; i < 200 * scale; i++) {
        uint64_t s[4] = {0, 0, 0, 0}, t[4] = {0, 0, 0, 0}, sum[4];
        RefPoint want, got;
        s[0] = rng64() % 64;
        t[0] = rng64() % 64;
        if (i % 2 == 0) {
            /* t = n - s gives s*G + (-s)*G = infinity */
            uint64_t c;
            t[0] = smx_subb(N_LIMBS[0], s[0], 0, &c);
            t[1] = smx_subb(N_LIMBS[1], 0, c, &c);
            t[2] = smx_subb(N_LIMBS[2], 0, c, &c);
            t[3] = smx_subb(N_LIMBS[3], 0, c, &c);
        }
        add_small(sum, t, s[0]);
        want = ref_mul(&g, sum);
        ec_double_mul_vt(&r, s, t, &base);
        got = from_prod(&r);
        CHECK("ec_double_mul_vt same base", points_equal(&got, &want));
    }
}

/* ---- public API on top of all this ---- */

static void test_public_points(void) {
    static const char *const id = "ALICE123@YAHOO.COM";
    long i;
    ECPoint inf = ec_point_infinity();
    ECPoint g = ec_point_generator();
    BigInt256 one = bigint256_one(), zero = bigint256_zero(), n = SM2_N;
    ECPoint r;
    printf("public point API\n");

    r = ec_point_multiply(g, &zero);
    CHECK("0*G is infinity", r.infinity);
    r = ec_point_multiply(g, &one);
    CHECK("1*G is G", !r.infinity && fp_equal(r.x, g.x) && fp_equal(r.y, g.y));
    r = ec_point_multiply(g, &n);
    CHECK("n*G is infinity", r.infinity);
    r = ec_point_multiply(inf, &one);
    CHECK("1*inf is infinity", r.infinity);
    r = ec_point_new(g.x, fp_add(g.y, fp_one()));
    r = ec_point_multiply(r, &one);
    CHECK("off-curve base is refused", r.infinity);
    r = sm2_get_public_key(&zero);
    CHECK("public key of 0", r.infinity);
    r = sm2_get_public_key(&n);
    CHECK("public key of n", r.infinity);
    r = ec_point_add(g, inf);
    CHECK("G + inf", fp_equal(r.x, g.x));
    r = ec_point_add(inf, g);
    CHECK("inf + G", fp_equal(r.x, g.x));
    r = ec_point_add(g, ec_point_new(g.x, fp_negate(g.y)));
    CHECK("G + (-G)", r.infinity);
    CHECK("infinity does not pass as a valid point", !ec_point_is_on_curve(&inf));
    CHECK("G on curve", ec_point_is_on_curve(&g));

    r = ec_point_from_hex_encoded("00");
    CHECK("short encoding is infinity", r.infinity);
    r = ec_point_from_hex_encoded("zz");
    CHECK("junk encoding is infinity", r.infinity);

    for (i = 0; i < 30 * scale; i++) {
        char pri[65], pub[131];
        char *sig, *ct, *pt;
        ECPoint p;
        size_t len = (size_t)(rng64() % 200) + 1;
        char *msg = (char *)malloc(len + 1);
        size_t j;
        for (j = 0; j < len; j++) {
            msg[j] = (char)(1 + rng64() % 255);
        }
        msg[len] = '\0';

        sm2_gen_keypair(pri, pub);
        p = ec_point_from_hex_encoded(pub);
        CHECK("generated key on curve", ec_point_is_on_curve(&p) && !p.infinity);

        sig = sm2_sign(id, msg, pri);
        CHECK("sign then verify", sm2_verify(id, sig, msg, pub));
        sig[3] = (char)(sig[3] == '0' ? '1' : '0');
        CHECK("tampered r rejected", !sm2_verify(id, sig, msg, pub));
        free(sig);

        ct = sm2_encrypt(msg, pub);
        pt = sm2_decrypt(ct, pri);
        CHECK("encrypt then decrypt", pt != NULL && strcmp(pt, msg) == 0);
        free(pt);
        free(ct);
        free(msg);
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        rng_state = strtoull(argv[1], NULL, 0);
    }
    if (argc > 2) {
        scale = atol(argv[2]);
    }
    test_field();
    test_order();
    test_generic();
    test_hex();
    test_tables();
    test_point_ops();
    test_recodings();
    test_scalar_mult();
    test_double_mult();
    test_public_points();
    printf("\n=== differential results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
