/*
 * Jacobian point arithmetic on y^2 = x^3 + b (x = X/Z^2, y = Y/Z^3, Z = 0 is infinity), written
 * once and included twice by sm9_curve.h: for G1 over Fq and for G2 on the twist over Fq2.
 * The includer defines
 *   PT, FE           the point and field types
 *   PT_FN(name)      the function name prefix
 *   FE_ADD, FE_SUB, FE_DBL, FE_MUL, FE_SQR, FE_NEG, FE_CMOV, FE_IS_ZERO, FE_EQUAL, FE_ONE_SET
 * Points must be in the prime-order group, or infinity: callers validate them first.
 */

static inline void PT_FN(set_infinity)(PT *r) {
    FE_ONE_SET(&r->x);
    FE_ONE_SET(&r->y);
    memset(&r->z, 0, sizeof(r->z));
}

static inline void PT_FN(cmov)(PT *r, const PT *a, uint64_t mask) {
    FE_CMOV(&r->x, &a->x, mask);
    FE_CMOV(&r->y, &a->y, mask);
    FE_CMOV(&r->z, &a->z, mask);
}

static inline void PT_FN(neg)(PT *r, const PT *a) {
    r->x = a->x;
    FE_NEG(&r->y, &a->y);
    r->z = a->z;
}

/* r = 2a (dbl-2009-l, a = 0), 2M + 5S. Infinity stays infinity: Z3 = 2YZ. */
static inline void PT_FN(dbl)(PT *r, const PT *p) {
    FE a, b, c, d, e, f, t;
    FE_SQR(&a, &p->x);
    FE_SQR(&b, &p->y);
    FE_SQR(&c, &b);
    FE_ADD(&d, &p->x, &b);
    FE_SQR(&d, &d);
    FE_SUB(&d, &d, &a);
    FE_SUB(&d, &d, &c);
    FE_DBL(&d, &d);
    FE_DBL(&e, &a);
    FE_ADD(&e, &e, &a);
    FE_SQR(&f, &e);
    FE_MUL(&t, &p->y, &p->z);
    FE_DBL(&r->z, &t);
    FE_DBL(&t, &d);
    FE_SUB(&r->x, &f, &t);
    FE_SUB(&t, &d, &r->x);
    FE_MUL(&t, &e, &t);
    FE_DBL(&c, &c);
    FE_DBL(&c, &c);
    FE_DBL(&c, &c);
    FE_SUB(&r->y, &t, &c);
}

/*
 * r = a + b, 12M + 4S. Handles infinity on either side and P + (-P). It cannot add a point to
 * itself: it returns all ones in that case, and the caller must supply 2a. Otherwise zero.
 */
static inline uint64_t PT_FN(add)(PT *r, const PT *a, const PT *b) {
    FE z1z1, z2z2, u1, u2, s1, s2, h, rr, hh, hhh, v, t;
    PT res;
    uint64_t inf_a = FE_IS_ZERO(&a->z), inf_b = FE_IS_ZERO(&b->z);
    uint64_t same;

    FE_SQR(&z1z1, &a->z);
    FE_SQR(&z2z2, &b->z);
    FE_MUL(&u1, &a->x, &z2z2);
    FE_MUL(&u2, &b->x, &z1z1);
    FE_MUL(&s1, &a->y, &b->z);
    FE_MUL(&s1, &s1, &z2z2);
    FE_MUL(&s2, &b->y, &a->z);
    FE_MUL(&s2, &s2, &z1z1);
    FE_SUB(&h, &u2, &u1);
    FE_SUB(&rr, &s2, &s1);
    same = FE_IS_ZERO(&h) & FE_IS_ZERO(&rr) & ~inf_a & ~inf_b;

    FE_SQR(&hh, &h);
    FE_MUL(&hhh, &hh, &h);
    FE_MUL(&v, &u1, &hh);
    FE_SQR(&res.x, &rr);
    FE_SUB(&res.x, &res.x, &hhh);
    FE_DBL(&t, &v);
    FE_SUB(&res.x, &res.x, &t);
    FE_SUB(&t, &v, &res.x);
    FE_MUL(&res.y, &rr, &t);
    FE_MUL(&t, &s1, &hhh);
    FE_SUB(&res.y, &res.y, &t);
    FE_MUL(&res.z, &a->z, &b->z);
    FE_MUL(&res.z, &res.z, &h);

    PT_FN(cmov)(&res, b, inf_a);
    PT_FN(cmov)(&res, a, inf_b);
    *r = res;
    return same;
}

/* r = a + b for every input; constant time, at the price of an extra doubling */
static inline void PT_FN(add_complete)(PT *r, const PT *a, const PT *b) {
    PT sum, dbl;
    uint64_t same = PT_FN(add)(&sum, a, b);
    PT_FN(dbl)(&dbl, a);
    PT_FN(cmov)(&sum, &dbl, same);
    *r = sum;
}

/*
 * r = a + b for every input, branching on a == b. The branch is taken only when two multiples
 * of a valid point collide, which the scalar schedules here never make happen, so for valid
 * input it does not depend on the data.
 */
static inline void PT_FN(add_vt)(PT *r, const PT *a, const PT *b) {
    PT sum;
    uint64_t same = PT_FN(add)(&sum, a, b);
    SMX_DECLASSIFY(&same, sizeof(same));
    if (same) {
        PT_FN(dbl)(&sum, a);
    }
    *r = sum;
}

/*
 * Reads every table entry, whichever one is wanted; mag 0 selects nothing (all zero). The sum
 * goes to a local buffer first: with sel possibly aliasing the table, clang's vectorizer added a
 * runtime overlap check, a forward branch that tools/check_ct_asm.py rightly refuses.
 */
static SMX_NOINLINE void PT_FN(select)(PT *sel, const PT table[SM9_WIN_ENTRIES], unsigned mag) {
    uint64_t acc[sizeof(PT) / sizeof(uint64_t)];
    const size_t words = sizeof(PT) / sizeof(uint64_t);
    size_t j, l;
    for (l = 0; l < words; l++) {
        acc[l] = 0;
    }
    for (j = 0; j < SM9_WIN_ENTRIES; j++) {
        const uint64_t *in = (const uint64_t *)&table[j];
        uint64_t mask = smx_mask_is_zero((uint64_t)(mag ^ (unsigned)(j + 1)));
        for (l = 0; l < words; l++) {
            acc[l] |= in[l] & mask;
        }
    }
    memcpy(sel, acc, sizeof(acc));
    smx_wipe(acc, sizeof(acc));
}

/*
 * r = k * base with a fixed signed window, constant time in k. The same argument as for SM2's
 * ec_mul_ct (sm2_ec.h) shows that only the last addition can meet a == b, so it alone uses
 * the complete formula.
 */
static inline void PT_FN(mul_ct)(PT *r, const PT *base, const uint64_t k_in[4]) {
    PT table[SM9_WIN_ENTRIES], acc, sel;
    FE ny;
    uint64_t k[4];
    int i, j;

    sm9_reduce_once(k, k_in, 0, SM9_N);
    table[0] = *base;
    for (i = 1; i < SM9_WIN_ENTRIES; i++) {
        if ((i & 1) != 0) {
            PT_FN(dbl)(&table[i], &table[i / 2]);
        } else {
            (void)PT_FN(add)(&table[i], &table[i - 1], base);
        }
    }
    PT_FN(set_infinity)(&acc);
    for (i = SM9_WIN_COUNT - 1; i >= 0; i--) {
        uint64_t negative;
        unsigned mag = sm9_booth_digit(k, i, &negative);
        if (i != SM9_WIN_COUNT - 1) {
            for (j = 0; j < SM9_WIN_BITS; j++) {
                PT_FN(dbl)(&acc, &acc);
            }
        }
        PT_FN(select)(&sel, table, mag);
        FE_NEG(&ny, &sel.y);
        FE_CMOV(&sel.y, &ny, negative);
        if (i == 0) {
            PT_FN(add_complete)(&acc, &acc, &sel);
        } else {
            (void)PT_FN(add)(&acc, &acc, &sel);
        }
    }
    *r = acc;
    smx_wipe(&sel, sizeof(sel));
    smx_wipe(&ny, sizeof(ny));
    smx_wipe(&acc, sizeof(acc));
    smx_wipe(table, sizeof(table));
    smx_wipe(k, sizeof(k));
}

/* r = k * base by width-5 NAF. Variable time: PUBLIC scalars only. */
static inline void PT_FN(mul_vt)(PT *r, const PT *base, const uint64_t k[4]) {
    int8_t naf[258];
    PT table[8], twice, acc, neg;
    int i, len = sm9_wnaf(naf, k);

    PT_FN(dbl)(&twice, base);
    table[0] = *base;
    for (i = 1; i < 8; i++) {
        PT_FN(add_vt)(&table[i], &table[i - 1], &twice);
    }
    PT_FN(set_infinity)(&acc);
    for (i = len - 1; i >= 0; i--) {
        PT_FN(dbl)(&acc, &acc);
        if (naf[i] > 0) {
            PT_FN(add_vt)(&acc, &acc, &table[(naf[i] - 1) / 2]);
        } else if (naf[i] < 0) {
            PT_FN(neg)(&neg, &table[(-naf[i] - 1) / 2]);
            PT_FN(add_vt)(&acc, &acc, &neg);
        }
    }
    *r = acc;
}

/* all ones if a and b are the same point (infinity included) */
static inline uint64_t PT_FN(equal)(const PT *a, const PT *b) {
    FE z1z1, z2z2, t1, t2;
    uint64_t inf_a = FE_IS_ZERO(&a->z), inf_b = FE_IS_ZERO(&b->z), eq;
    FE_SQR(&z1z1, &a->z);
    FE_SQR(&z2z2, &b->z);
    FE_MUL(&t1, &a->x, &z2z2);
    FE_MUL(&t2, &b->x, &z1z1);
    eq = FE_EQUAL(&t1, &t2);
    FE_MUL(&z1z1, &z1z1, &a->z);
    FE_MUL(&z2z2, &z2z2, &b->z);
    FE_MUL(&t1, &a->y, &z2z2);
    FE_MUL(&t2, &b->y, &z1z1);
    eq &= FE_EQUAL(&t1, &t2);
    return (inf_a & inf_b) | (~inf_a & ~inf_b & eq);
}
