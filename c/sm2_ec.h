/*
 * SM2 curve arithmetic in Jacobian coordinates (x = X/Z^2, y = Y/Z^3, Z = 0 is
 * the point at infinity), exploiting a = -3.
 *
 * Scalar multiplications, chosen by whether the scalar is secret:
 *   ec_mul_g          constant time, k*G from fixed tables, no doublings
 *   ec_mul_ct         constant time, k*P with a fixed signed window
 *   ec_mul_vt         variable time wNAF, PUBLIC scalars only
 *   ec_double_mul_vt  variable time s*G + t*P (Shamir), PUBLIC scalars only
 *
 * All of them need a point in the prime-order group, or infinity; callers validate
 * points first. Constant time here means that no branch and no memory access depends on
 * the scalar.
 *
 * Internal header, included by sm2.c and the tests.
 */
#ifndef SMX_SM2_EC_H
#define SMX_SM2_EC_H

#include "sm2_fn.h"
#include "sm2_fp.h"
#include "sm2_precomp.inc"

typedef struct {
    Fe x, y, z;
} Jac;

/* signed window for variable-base constant-time multiplication */
#define EC_VAR_BITS 5
#define EC_VAR_ENTRIES (1 << (EC_VAR_BITS - 1))
#define EC_VAR_WINDOWS (256 / EC_VAR_BITS + 1)

/* wNAF width for the variable base in public-scalar multiplication */
#define EC_NAF_P_WIDTH 5
#define EC_NAF_P_ENTRIES (1 << (EC_NAF_P_WIDTH - 2))

static const Fe EC_GX = {0x715A4589334C74C7ULL, 0x8FE30BBFF2660BE1ULL, 0x5F9904466A39C994ULL,
                         0x32C4AE2C1F198119ULL};
static const Fe EC_GY = {0x02DF32E52139F0A0ULL, 0xD0A9877CC62A4740ULL, 0x59BDCEE36B692153ULL,
                         0xBC3736A2F4F6779CULL};

static inline void jac_set_affine(Jac *r, const Fe x, const Fe y) {
    fe_copy(r->x, x);
    fe_copy(r->y, y);
    fe_copy(r->z, FE_ONE);
}

static inline void jac_set_infinity(Jac *r) {
    fe_copy(r->x, FE_ONE);
    fe_copy(r->y, FE_ONE);
    r->z[0] = r->z[1] = r->z[2] = r->z[3] = 0;
}

static inline void jac_cmov(Jac *r, const Jac *a, uint64_t mask) {
    fe_cmov(r->x, a->x, mask);
    fe_cmov(r->y, a->y, mask);
    fe_cmov(r->z, a->z, mask);
}

/*
 * r = 2a, with alpha = 3(X - Z^2)(X + Z^2) from a = -3. Complete: Z3 = 2YZ
 * becomes 0 exactly when the input is infinity or has order 2.
 */
static inline void jac_double(Jac *r, const Jac *a) {
    Fe delta, gamma, beta, alpha, t, u, x3, y3, z3;

    fe_sqr(delta, a->z);
    fe_sqr(gamma, a->y);
    fe_mul(beta, a->x, gamma);
    fe_sub(t, a->x, delta);
    fe_add(u, a->x, delta);
    fe_mul(alpha, t, u);
    fe_mul_small(alpha, alpha, 3);

    fe_sqr(x3, alpha);
    fe_mul_small(t, beta, 8);
    fe_sub(x3, x3, t);

    fe_mul(z3, a->y, a->z);
    fe_add(z3, z3, z3);

    fe_mul_small(t, beta, 4);
    fe_sub(t, t, x3);
    fe_mul(y3, alpha, t);
    fe_sqr(u, gamma);
    fe_mul_small(u, u, 8);
    fe_sub(y3, y3, u);

    fe_copy(r->x, x3);
    fe_copy(r->y, y3);
    fe_copy(r->z, z3);
}

/*
 * r = a + b, 12M + 4S. Handles infinity on either side and P + (-P) (H = 0 makes
 * Z3 = 0). The one case the formula cannot do is a == b: it returns all ones for
 * that case, and the caller must supply 2a. Otherwise returns zero.
 */
static inline uint64_t jac_add(Jac *r, const Jac *a, const Jac *b) {
    Fe z1z1, z2z2, u1, u2, s1, s2, h, rr, hh, hhh, v, t;
    Jac res;
    uint64_t inf_a = fe_is_zero(a->z), inf_b = fe_is_zero(b->z);
    uint64_t same;

    fe_sqr(z1z1, a->z);
    fe_sqr(z2z2, b->z);
    fe_mul(u1, a->x, z2z2);
    fe_mul(u2, b->x, z1z1);
    fe_mul(s1, a->y, b->z);
    fe_mul(s1, s1, z2z2);
    fe_mul(s2, b->y, a->z);
    fe_mul(s2, s2, z1z1);
    fe_sub(h, u2, u1);
    fe_sub(rr, s2, s1);
    same = fe_is_zero(h) & fe_is_zero(rr) & ~inf_a & ~inf_b;

    fe_sqr(hh, h);
    fe_mul(hhh, hh, h);
    fe_mul(v, u1, hh);
    fe_sqr(res.x, rr);
    fe_sub(res.x, res.x, hhh);
    fe_add(t, v, v);
    fe_sub(res.x, res.x, t);
    fe_sub(t, v, res.x);
    fe_mul(res.y, rr, t);
    fe_mul(t, s1, hhh);
    fe_sub(res.y, res.y, t);
    fe_mul(res.z, a->z, b->z);
    fe_mul(res.z, res.z, h);

    jac_cmov(&res, b, inf_a);
    jac_cmov(&res, a, inf_b);
    *r = res;
    return same;
}

/*
 * r = a + (x2, y2), mixed addition, 8M + 3S. The affine point is treated as
 * infinity when nonzero is zero. Same contract as jac_add for a == b.
 */
static inline uint64_t jac_add_affine(Jac *r, const Jac *a, const Fe x2, const Fe y2,
                                      uint64_t nonzero) {
    Fe z1z1, u2, s2, h, rr, hh, hhh, v, t;
    Jac res, b;
    uint64_t inf_a = fe_is_zero(a->z);
    uint64_t same;

    fe_sqr(z1z1, a->z);
    fe_mul(u2, x2, z1z1);
    fe_mul(s2, y2, a->z);
    fe_mul(s2, s2, z1z1);
    fe_sub(h, u2, a->x);
    fe_sub(rr, s2, a->y);
    same = fe_is_zero(h) & fe_is_zero(rr) & ~inf_a & nonzero;

    fe_sqr(hh, h);
    fe_mul(hhh, hh, h);
    fe_mul(v, a->x, hh);
    fe_sqr(res.x, rr);
    fe_sub(res.x, res.x, hhh);
    fe_add(t, v, v);
    fe_sub(res.x, res.x, t);
    fe_sub(t, v, res.x);
    fe_mul(res.y, rr, t);
    fe_mul(t, a->y, hhh);
    fe_sub(res.y, res.y, t);
    fe_mul(res.z, a->z, h);

    jac_set_affine(&b, x2, y2);
    jac_cmov(&res, &b, inf_a);
    jac_cmov(&res, a, ~nonzero);
    *r = res;
    return same;
}

/* r = a + b for every input combination; constant time, costs an extra doubling. */
static inline void jac_add_complete(Jac *r, const Jac *a, const Jac *b) {
    Jac sum, dbl;
    uint64_t same = jac_add(&sum, a, b);
    jac_double(&dbl, a);
    jac_cmov(&sum, &dbl, same);
    *r = sum;
}

/* r = a + b for every input combination, branching on the (public) P == Q case. */
static inline void jac_add_vt(Jac *r, const Jac *a, const Jac *b) {
    Jac sum;
    if (jac_add(&sum, a, b)) {
        jac_double(&sum, a);
    }
    *r = sum;
}

/*
 * Signed window digit i of a 256-bit scalar (Booth recoding): the magnitude is in
 * [0, 2^(bits-1)] and the digits satisfy k = sum(+-mag_i * 2^(bits * i)). Shifts
 * and limb indices depend only on the public position i.
 */
static inline unsigned ec_booth_digit(const uint64_t k[4], int bits, int i, uint64_t *negative) {
    uint64_t w, sign, d;
    const uint64_t mask = ((uint64_t)1 << (bits + 1)) - 1;

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

/*
 * The two table scans read every entry, whichever one is wanted. They stay out of line so
 * that tools/check_ct_asm.py can inspect exactly the code that runs: no conditional jump
 * may skip a load.
 */
static SMX_NOINLINE void ec_comb_select(uint64_t sel[8], int window, unsigned mag) {
    int j, l;
    for (l = 0; l < 8; l++) {
        sel[l] = 0;
    }
    for (j = 0; j < SMX_COMB_ENTRIES; j++) {
        uint64_t mask = smx_mask_is_zero((uint64_t)(mag ^ (unsigned)(j + 1)));
        for (l = 0; l < 8; l++) {
            sel[l] |= sm2_comb[window][j][l] & mask;
        }
    }
}

static SMX_NOINLINE void ec_var_select(Jac *sel, const Jac table[EC_VAR_ENTRIES], unsigned mag) {
    int j, l;
    for (l = 0; l < 4; l++) {
        sel->x[l] = 0;
        sel->y[l] = 0;
        sel->z[l] = 0;
    }
    for (j = 0; j < EC_VAR_ENTRIES; j++) {
        uint64_t mask = smx_mask_is_zero((uint64_t)(mag ^ (unsigned)(j + 1)));
        for (l = 0; l < 4; l++) {
            sel->x[l] |= table[j].x[l] & mask;
            sel->y[l] |= table[j].y[l] & mask;
            sel->z[l] |= table[j].z[l] & mask;
        }
    }
}

/*
 * r = k*G. Windows of the 256-bit scalar index a per-window table, so there are
 * only mixed additions and no doublings. Every table entry of the window is read
 * and masked, so memory access does not depend on the digit.
 */
static inline void ec_mul_g(Jac *r, const uint64_t k_in[4]) {
    uint64_t k[4];
    Jac acc;
    int i;

    /* the no-exception argument below needs k < n; G has order n, so this changes nothing */
    fn_reduce(k, k_in);

    /*
     * jac_add_affine never sees a point added to itself. Let S be the integer sum of the
     * lower windows and D = +-d * 2^(bits * i) the next. Below the top window,
     * |S| < 2^(bits * i) <= |D| and |S| + |D| < n, so S != D mod n. In the top window
     * D can be 2^256, which needs bits 254 and 255 of k set, and then S - D = k - 2^257 is
     * not a multiple of n either. The test sweeps k around 0 and n to back this up.
     */
    jac_set_infinity(&acc);
    for (i = 0; i < SMX_COMB_WINDOWS; i++) {
        uint64_t negative;
        unsigned mag = ec_booth_digit(k, SMX_COMB_BITS, i, &negative);
        uint64_t sel[8];
        Fe y;
        ec_comb_select(sel, i, mag);
        fe_cond_neg(y, sel + 4, negative);
        (void)jac_add_affine(&acc, &acc, sel, y, ~smx_mask_is_zero((uint64_t)mag));
        smx_wipe(sel, sizeof(sel));
        smx_wipe(y, sizeof(y));
    }
    smx_wipe(k, sizeof(k));
    *r = acc;
    smx_wipe(&acc, sizeof(acc));
}

/*
 * r = k*base with a fixed signed window, for any 256-bit k. base must be in the
 * prime-order group, or infinity.
 *
 * jac_add cannot add a point to itself, which can only happen on the last addition.
 * Before that, with i >= 1, the accumulator is A * base with A a multiple of 2^bits and
 * |A| <= n/32 + 1, and the digit d has |d| <= 2^(bits-1). A = +-d mod n then needs A = 0,
 * the infinity case that jac_add handles. In the last addition it does occur, for example
 * for k = n - 6, where it is -3P + -3P, so that one always uses the complete formula. No
 * branch depends on the scalar.
 */
static inline void ec_mul_ct(Jac *r, const Jac *base, const uint64_t k_in[4]) {
    Jac table[EC_VAR_ENTRIES];
    Jac acc;
    uint64_t k[4];
    int i;

    fn_reduce(k, k_in);

    table[0] = *base;
    for (i = 1; i < EC_VAR_ENTRIES; i++) {
        if ((i & 1) != 0) {
            jac_double(&table[i], &table[i / 2]);
        } else {
            (void)jac_add(&table[i], &table[i - 1], base);
        }
    }

    jac_set_infinity(&acc);
    for (i = EC_VAR_WINDOWS - 1; i >= 0; i--) {
        uint64_t negative;
        unsigned mag = ec_booth_digit(k, EC_VAR_BITS, i, &negative);
        Jac sel;
        int j;
        if (i != EC_VAR_WINDOWS - 1) {
            for (j = 0; j < EC_VAR_BITS; j++) {
                jac_double(&acc, &acc);
            }
        }
        ec_var_select(&sel, table, mag);
        fe_cond_neg(sel.y, sel.y, negative);
        if (i == 0) {
            jac_add_complete(&acc, &acc, &sel);
        } else {
            (void)jac_add(&acc, &acc, &sel);
        }
        smx_wipe(&sel, sizeof(sel));
    }
    smx_wipe(k, sizeof(k));
    *r = acc;
    smx_wipe(&acc, sizeof(acc));
    smx_wipe(table, sizeof(table));
}

/*
 * Width-w NAF of k, least significant digit first. Variable time.
 * out must have room for 257 digits; returns the digit count.
 */
static inline int ec_wnaf(int8_t out[257], const uint64_t k_in[4], int width) {
    uint64_t k[5];
    const uint64_t window = (uint64_t)1 << width;
    int len = 0;

    k[0] = k_in[0];
    k[1] = k_in[1];
    k[2] = k_in[2];
    k[3] = k_in[3];
    k[4] = 0;
    while ((k[0] | k[1] | k[2] | k[3] | k[4]) != 0) {
        int digit = 0;
        if ((k[0] & 1) != 0) {
            uint64_t c;
            uint64_t low = k[0] & (window - 1);
            if (low >= (window >> 1)) {
                /* negative digit: k += window - low */
                digit = (int)low - (int)window;
                k[0] = smx_addc(k[0], window - low, 0, &c);
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

/* table[j] = (2j + 1) * base, for j < EC_NAF_P_ENTRIES. */
static inline void ec_naf_table(Jac table[EC_NAF_P_ENTRIES], const Jac *base) {
    Jac twice;
    int j;
    jac_double(&twice, base);
    table[0] = *base;
    for (j = 1; j < EC_NAF_P_ENTRIES; j++) {
        jac_add_vt(&table[j], &table[j - 1], &twice);
    }
}

static inline void ec_add_naf_digit(Jac *acc, const Jac table[EC_NAF_P_ENTRIES], int digit) {
    if (digit > 0) {
        jac_add_vt(acc, acc, &table[(digit - 1) / 2]);
    } else if (digit < 0) {
        Jac q = table[(-digit - 1) / 2];
        fe_cond_neg(q.y, q.y, ~(uint64_t)0);
        jac_add_vt(acc, acc, &q);
    }
}

/* r = k*base. Variable time: for PUBLIC scalars only. */
static inline void ec_mul_vt(Jac *r, const Jac *base, const uint64_t k[4]) {
    int8_t naf[257];
    Jac table[EC_NAF_P_ENTRIES];
    Jac acc;
    int i, len = ec_wnaf(naf, k, EC_NAF_P_WIDTH);

    ec_naf_table(table, base);
    jac_set_infinity(&acc);
    for (i = len - 1; i >= 0; i--) {
        jac_double(&acc, &acc);
        ec_add_naf_digit(&acc, table, naf[i]);
    }
    *r = acc;
}

/*
 * r = s*G + t*base by interleaved wNAF, sharing one run of doublings. Variable
 * time: for PUBLIC scalars only, that is, signature verification.
 */
static inline void ec_double_mul_vt(Jac *r, const uint64_t s[4], const uint64_t t[4],
                                    const Jac *base) {
    int8_t naf_s[257], naf_t[257];
    Jac table[EC_NAF_P_ENTRIES];
    Jac acc;
    int len_s = ec_wnaf(naf_s, s, SMX_NAF_G_WIDTH);
    int len_t = ec_wnaf(naf_t, t, EC_NAF_P_WIDTH);
    int i;

    ec_naf_table(table, base);
    jac_set_infinity(&acc);
    for (i = (len_s > len_t ? len_s : len_t) - 1; i >= 0; i--) {
        jac_double(&acc, &acc);
        if (i < len_s && naf_s[i] != 0) {
            int d = naf_s[i];
            const uint64_t *g = sm2_naf_g[((d < 0 ? -d : d) - 1) / 2];
            Fe y;
            fe_cond_neg(y, g + 4, d < 0 ? ~(uint64_t)0 : 0);
            if (jac_add_affine(&acc, &acc, g, y, ~(uint64_t)0)) {
                Jac q;
                jac_set_affine(&q, g, y);
                jac_double(&acc, &q);
            }
        }
        if (i < len_t) {
            ec_add_naf_digit(&acc, table, naf_t[i]);
        }
    }
    *r = acc;
}

#endif /* SMX_SM2_EC_H */
