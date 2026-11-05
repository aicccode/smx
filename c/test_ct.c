/*
 * Constant-time check, in the style of ctgrind: secrets are marked as uninitialized
 * and MemorySanitizer aborts on any branch or memory address that depends on them.
 * It sees the code as compiled for this check, which is close to, but not the same
 * as, a release build.
 *
 *   make check-ct     (needs clang)
 *
 * Passing means no secret-dependent branch or address on the paths exercised here.
 * Includes the implementation files so it can reach the static SM4 functions.
 */
#include "sm2_ec.h"
#include "sm4.c"
#include <sanitizer/msan_interface.h>
#include <stdio.h>

#define SECRET(ptr, size) __msan_poison((ptr), (size))
#define PUBLIC(ptr, size) __msan_unpoison((ptr), (size))

static void test_scalar_mult(void) {
    /* a mix of ordinary scalars and ones that end in zero or negative digits */
    static const uint64_t scalars[][4] = {
        {0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL, 0x1111111111111111ULL,
         0x2222222222222222ULL},
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0x7FFFFFFFFFFFFFFFULL,
         0x0000000000000001ULL},
        {0x8000000000000000ULL, 0, 0, 0x4000000000000000ULL},
        {0x53BBF40939D54100ULL, 0x7203DF6B21C6052BULL, 0xFFFFFFFFFFFFFFFFULL,
         0xFFFFFFFEFFFFFFFFULL},
    };
    size_t i;
    Jac base;
    jac_set_affine(&base, EC_GX, EC_GY);
    jac_double(&base, &base);

    for (i = 0; i < sizeof(scalars) / sizeof(scalars[0]); i++) {
        uint64_t k[4];
        Jac r;
        memcpy(k, scalars[i], sizeof(k));
        SECRET(k, sizeof(k));
        ec_mul_g(&r, k);
        PUBLIC(&r, sizeof(r));
        ec_mul_ct(&r, &base, k);
        PUBLIC(&r, sizeof(r));
    }
}

static void test_field_and_order(void) {
    uint64_t a[4] = {1, 2, 3, 4}, b[4] = {5, 6, 7, 8}, r[4];
    BigInt256 x, y, m, out;

    SECRET(a, sizeof(a));
    SECRET(b, sizeof(b));

    fe_mul(r, a, b);
    fe_sqr(r, a);
    fe_add(r, a, b);
    fe_sub(r, a, b);
    fe_cond_neg(r, a, ~(uint64_t)0);
    fe_mul_small(r, a, 8);
    fe_inv(r, a);
    fn_mul(r, a, b);
    fn_reduce(r, a);
    fn_inv(r, a);

    memcpy(x.limbs, a, sizeof(a));
    memcpy(y.limbs, b, sizeof(b));
    memcpy(m.limbs, FN_N, sizeof(FN_N));
    bigint256_mod_add(&out, &x, &y, &m);
    bigint256_mod_sub(&out, &x, &y, &m);
    (void)bigint256_add(&out, &x, &y);
    (void)bigint256_sub(&out, &x, &y);
    {
        int c = bigint256_compare(&x, &y);
        (void)c;
    }
}

static void test_hex(void) {
    uint8_t secret[48], back[48];
    char hex[97];
    size_t len;
    for (len = 0; len < 48; len += 5) {
        memset(secret, 0xA5, sizeof(secret));
        SECRET(secret, len);
        smx_hex_encode(secret, len, hex, 'a');
        smx_hex_decode(hex, len, back);
    }
}

static void test_sm4_hardware(void) {
    uint32_t rk[32], iv[4] = {1, 2, 3, 4};
    uint8_t in[SM4_MAX_LANES * 16], out[SM4_MAX_LANES * 16];
    char hex[33];
    int i;

    if (sm4_lanes == 1) {
        /* tier 0 indexes tables by secret data by design, see sm4_t_table */
        printf("  no hardware SM4 path on this CPU or build\n");
        return;
    }
    for (i = 0; i < 32; i++) {
        rk[i] = (uint32_t)i * 0x01010101u;
    }
    memset(in, 0x5A, sizeof(in));
    SECRET(rk, sizeof(rk));
    SECRET(in, sizeof(in));
    sm4_blocks(rk, in, out);
    SECRET(iv, sizeof(iv));
    sm4_cbc_encrypt_blocks(rk, iv, in, 1, hex);
}

int main(void) {
    test_scalar_mult();
    test_field_and_order();
    test_hex();
    test_sm4_hardware();
    printf("constant-time check passed\n");
    return 0;
}
