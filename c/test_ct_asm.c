/*
 * Compiled by tools/check_ct_asm.py, never run for its result: each ct_* function holds
 * code that handles secrets, reached through a pointer table so that nothing is folded
 * into constants. The script then reads the machine code for forbidden branches.
 */
#include "sm2_ec.h"
#include "sm2_support_ct.h"
#include "sm9_pairing.h"
#include "bigint256.c"
#include "sm4.c"

#define CT __attribute__((noinline, used))

CT void ct_comb_select(uint64_t s[8], int w, unsigned m) {
    ec_comb_select(s, w, m);
}
CT void ct_var_select(Jac *s, const Jac *t, unsigned m) {
    ec_var_select(s, t, m);
}
CT unsigned ct_booth(const uint64_t k[4], uint64_t *n) {
    return ec_booth_digit(k, EC_VAR_BITS, 7, n);
}
CT void ct_fe_cmov(Fe r, const Fe a, uint64_t m) {
    fe_cmov(r, a, m);
}
CT uint64_t ct_fe_is_zero(const Fe a) {
    return fe_is_zero(a);
}
CT uint64_t ct_fe_equal(const Fe a, const Fe b) {
    return fe_equal(a, b);
}
CT void ct_fe_add(Fe r, const Fe a, const Fe b) {
    fe_add(r, a, b);
}
CT void ct_fe_sub(Fe r, const Fe a, const Fe b) {
    fe_sub(r, a, b);
}
CT void ct_fe_mul(Fe r, const Fe a, const Fe b) {
    fe_mul(r, a, b);
}
CT void ct_fe_sqr(Fe r, const Fe a) {
    fe_sqr(r, a);
}
CT void ct_fe_small(Fe r, const Fe a) {
    fe_mul_small(r, a, 8);
}
CT void ct_fe_neg(Fe r, const Fe a, uint64_t m) {
    fe_cond_neg(r, a, m);
}
CT void ct_fe_inv(Fe r, const Fe a) {
    fe_inv(r, a);
}
CT void ct_fn_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    fn_mul(r, a, b);
}
CT void ct_fn_inv(uint64_t r[4], const uint64_t a[4]) {
    fn_inv(r, a);
}
CT void ct_jac_double(Jac *r, const Jac *a) {
    jac_double(r, a);
}
CT uint64_t ct_jac_add(Jac *r, const Jac *a, const Jac *b) {
    return jac_add(r, a, b);
}
CT uint64_t ct_jac_add_affine(Jac *r, const Jac *a, const Fe x, const Fe y, uint64_t nz) {
    return jac_add_affine(r, a, x, y, nz);
}
CT void ct_jac_complete(Jac *r, const Jac *a, const Jac *b) {
    jac_add_complete(r, a, b);
}
CT void ct_mod_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4], const uint64_t m[4]) {
    smx_mod_add(r, a, b, m);
}
CT void ct_mod_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4], const uint64_t m[4]) {
    smx_mod_sub(r, a, b, m);
}
CT int ct_compare(const uint64_t a[4], const uint64_t b[4]) {
    return smx_compare(a, b);
}
CT uint64_t ct_pkcs7(const uint8_t b[32], size_t *n) {
    return pkcs7_check(b, 32, n);
}
CT char ct_hex_digit(unsigned n, unsigned delta) {
    return hex_digit(n, delta);
}
CT unsigned ct_hex_nibble(char c, unsigned *bad) {
    return hex_nibble(c, bad, 0x20u);
}
CT unsigned ct_hex_nibble_lower(char c, unsigned *bad) {
    return hex_nibble(c, bad, 0u);
}
#ifdef SMX_HAVE_SSE2
CT void ct_hex_encode_block(const uint8_t *d, char *o) {
    hex_encode_block(d, o, 39);
}
#endif
CT uint32_t ct_sbox_circuit(uint32_t x) {
    return sm4_sbox_circuit(x);
}
CT void ct_sm4_scalar(const uint32_t rk[32], const uint8_t *in, uint8_t *out) {
    sm4_scalar_blocks(rk, in, out);
}
#ifdef SMX_SM4_X86
CT void ct_sm4_gfni(const uint32_t rk[32], const uint8_t *in, uint8_t *out) {
    sm4_gfni_blocks(rk, in, out);
}
CT void ct_sm4_aesni256(const uint32_t rk[32], const uint8_t *in, uint8_t *out) {
    sm4_aesni256_blocks(rk, in, out);
}
CT void ct_sm4_aesni128(const uint32_t rk[32], const uint8_t *in, uint8_t *out) {
    sm4_aesni128_blocks(rk, in, out);
}
#endif
#ifdef SMX_SM4_NEON
CT void ct_sm4_neon(const uint32_t rk[32], const uint8_t *in, uint8_t *out) {
    sm4_neon_blocks(rk, in, out);
}
#endif
CT int ct_bytes_equal(const uint8_t *a, const uint8_t *b) {
    return bytes_equal(a, b, 32);
}

/* SM9: the field tower, the point formulas, the table scans and the scalar recoding */
CT void ct_fq_mul(fq_t *r, const fq_t *a, const fq_t *b) {
    fq_mul(r, a, b);
}
CT void ct_fq_add(fq_t *r, const fq_t *a, const fq_t *b) {
    fq_add(r, a, b);
}
CT void ct_fq_sub(fq_t *r, const fq_t *a, const fq_t *b) {
    fq_sub(r, a, b);
}
CT void ct_fq_inv(fq_t *r, const fq_t *a) {
    fq_inv(r, a);
}
CT uint64_t ct_fq_from_bytes(fq_t *r, const uint8_t in[32]) {
    return fq_from_bytes(r, in);
}
CT void ct_fq2_mul(fq2_t *r, const fq2_t *a, const fq2_t *b) {
    fq2_mul(r, a, b);
}
CT void ct_fq2_sqr(fq2_t *r, const fq2_t *a) {
    fq2_sqr(r, a);
}
CT void ct_fq2_inv(fq2_t *r, const fq2_t *a) {
    fq2_inv(r, a);
}
CT void ct_fq12_mul(fq12_t *r, const fq12_t *a, const fq12_t *b) {
    fq12_mul(r, a, b);
}
CT void ct_fq12_sqr(fq12_t *r, const fq12_t *a) {
    fq12_sqr(r, a);
}
CT void ct_fq12_cyclo_sqr(fq12_t *r, const fq12_t *a) {
    fq12_cyclo_sqr(r, a);
}
CT void ct_fq12_mul_line(fq12_t *f, const fq2_t *a, const fq2_t *b, const fq2_t *c) {
    fq12_mul_line(f, a, b, c);
}
CT void ct_fq12_inv(fq12_t *r, const fq12_t *a) {
    fq12_inv(r, a);
}
CT void ct_sm9_dbl_step(g2_t *t, fq12_t *f, const sm9_line_point *p) {
    sm9_dbl_step(t, f, p);
}
CT void ct_sm9_add_step(g2_t *t, fq12_t *f, const fq2_t *x, const fq2_t *y,
                        const sm9_line_point *p) {
    sm9_add_step(t, f, x, y, p);
}
CT void ct_g1_dbl(g1_t *r, const g1_t *a) {
    g1_dbl(r, a);
}
CT uint64_t ct_g1_add(g1_t *r, const g1_t *a, const g1_t *b) {
    return g1_add(r, a, b);
}
CT void ct_g1_complete(g1_t *r, const g1_t *a, const g1_t *b) {
    g1_add_complete(r, a, b);
}
CT void ct_g2_dbl(g2_t *r, const g2_t *a) {
    g2_dbl(r, a);
}
CT uint64_t ct_g2_add(g2_t *r, const g2_t *a, const g2_t *b) {
    return g2_add(r, a, b);
}
CT void ct_g2_complete(g2_t *r, const g2_t *a, const g2_t *b) {
    g2_add_complete(r, a, b);
}
CT void ct_g1_select(g1_t *s, const g1_t *t, unsigned m) {
    g1_select(s, t, m);
}
CT void ct_g2_select(g2_t *s, const g2_t *t, unsigned m) {
    g2_select(s, t, m);
}
CT void ct_gt_select(fq12_t *s, const fq12_t *t, unsigned d) {
    sm9_gt_select(s, t, d);
}
CT unsigned ct_sm9_booth(const uint64_t k[4], uint64_t *n) {
    return sm9_booth_digit(k, 7, n);
}
CT uint64_t ct_g1_from_bytes(g1_t *r, const uint8_t in[65]) {
    return g1_from_bytes(r, in);
}
CT void ct_sm9n_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    sm9n_mul(r, a, b);
}
CT void ct_sm9n_inv(uint64_t r[4], const uint64_t a[4]) {
    sm9n_inv(r, a);
}

/* Referenced from main, so that link-time optimization has to keep them all. */
void (*volatile ct_keep[])(void) = {
    (void (*)(void))ct_comb_select,  (void (*)(void))ct_var_select,
    (void (*)(void))ct_booth,        (void (*)(void))ct_fe_cmov,
    (void (*)(void))ct_fe_is_zero,   (void (*)(void))ct_fe_equal,
    (void (*)(void))ct_fe_add,       (void (*)(void))ct_fe_sub,
    (void (*)(void))ct_fe_mul,       (void (*)(void))ct_fe_sqr,
    (void (*)(void))ct_fe_small,     (void (*)(void))ct_fe_neg,
    (void (*)(void))ct_fe_inv,       (void (*)(void))ct_fn_mul,
    (void (*)(void))ct_fn_inv,       (void (*)(void))ct_jac_double,
    (void (*)(void))ct_jac_add,      (void (*)(void))ct_jac_add_affine,
    (void (*)(void))ct_jac_complete, (void (*)(void))ct_mod_add,
    (void (*)(void))ct_mod_sub,      (void (*)(void))ct_compare,
    (void (*)(void))ct_pkcs7,        (void (*)(void))ct_hex_digit,
    (void (*)(void))ct_hex_nibble,   (void (*)(void))ct_hex_nibble_lower,
    (void (*)(void))ct_sbox_circuit, (void (*)(void))ct_sm4_scalar,
    (void (*)(void))ct_bytes_equal,  (void (*)(void))ct_fq_mul,
    (void (*)(void))ct_fq_add,       (void (*)(void))ct_fq_sub,
    (void (*)(void))ct_fq_inv,       (void (*)(void))ct_fq_from_bytes,
    (void (*)(void))ct_fq2_mul,      (void (*)(void))ct_fq2_sqr,
    (void (*)(void))ct_fq2_inv,      (void (*)(void))ct_fq12_mul,
    (void (*)(void))ct_fq12_sqr,     (void (*)(void))ct_fq12_cyclo_sqr,
    (void (*)(void))ct_fq12_mul_line, (void (*)(void))ct_fq12_inv,
    (void (*)(void))ct_sm9_dbl_step, (void (*)(void))ct_sm9_add_step,
    (void (*)(void))ct_g1_dbl,       (void (*)(void))ct_g1_add,
    (void (*)(void))ct_g1_complete,  (void (*)(void))ct_g2_dbl,
    (void (*)(void))ct_g2_add,       (void (*)(void))ct_g2_complete,
    (void (*)(void))ct_g1_select,    (void (*)(void))ct_g2_select,
    (void (*)(void))ct_gt_select,    (void (*)(void))ct_sm9_booth,
    (void (*)(void))ct_g1_from_bytes, (void (*)(void))ct_sm9n_mul,
    (void (*)(void))ct_sm9n_inv,
};

int main(void) {
    return ct_keep[0] == 0;
}
