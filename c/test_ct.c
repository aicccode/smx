/*
 * Constant-time check, in the style of ctgrind: secrets are marked as uninitialized
 * and MemorySanitizer aborts on any branch or memory address that depends on them.
 * It sees the code as compiled for this check, which is close to, but not the same
 * as, a release build.
 *
 *   make check-ct     (needs clang)
 *
 * Passing means no secret-dependent branch or address on the paths exercised here.
 * SM4's block cipher is not among them: on this branch it uses secret-indexed tables (the
 * `security` branch has the constant-time SM4). Its PKCS#7 check still is. Includes the
 * implementation files so it can reach the static SM4 functions.
 */
#include "sm2_ec.h"
#include "sm2.c"
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
        smx_hex_decode_lower(hex, len, back);
    }
}

/* The SM4 padding check reads every byte the same way, whatever it holds. */
static void test_sm4_padding(void) {
    size_t plain_len;
    uint8_t padded[32];
    memset(padded, 0x04, sizeof(padded));
    SECRET(padded, sizeof(padded));
    (void)pkcs7_check(padded, sizeof(padded), &plain_len);
}

/*
 * The public API end to end, with the private key hex poisoned, and the nonces poisoned
 * because they come from a syscall MSan does not know about. Needs MSAN_OPTIONS
 * intercept_strlen=0, as the length of a key is public but its bytes are not.
 */
static void test_full_operations(void) {
    char pri[65] = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
    static const char pub[] = "0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"
                              "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13";
    static const char ct[] = "0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73"
                             "e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0"
                             "59983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd8766"
                             "21886ca989ca9c7d58087307ca93092d651efa";
    char gen_pri[65], gen_pub[131];
    char *out;
    BigInt256 d, r;
    ECPoint q, rq;
    SM2KeySwapParams kx;
    uint8_t sb[32];

    SECRET(pri, 64);
    out = sm2_sign("1234567812345678", "message digest", pri);
    if (out == NULL) {
        printf("sign failed\n");
    }
    free(out);

    out = sm2_decrypt(ct, pri);
    if (out == NULL) {
        printf("decrypt failed\n");
    }
    free(out);

    out = sm2_encrypt("encryption standard", pub);
    if (out == NULL) {
        printf("encrypt failed\n");
    }
    free(out);

    sm2_gen_keypair(gen_pri, gen_pub);

    d = bigint256_from_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
    r = bigint256_from_hex("0FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE");
    q = sm2_get_public_key(&d);
    rq = sm2_get_public_key(&r);
    SECRET(&d, sizeof(d));
    SECRET(&r, sizeof(r));
    kx = sm2_get_sb(16, q, rq, q, &d, rq, &r, "a", "b");
    PUBLIC(&kx, sizeof(kx));
    memset(sb, 0, sizeof(sb));
    kx = sm2_get_sa(16, q, rq, q, &d, rq, &r, "a", "b", sb, 32);
    PUBLIC(&kx, sizeof(kx));
}

int main(void) {
    test_scalar_mult();
    test_field_and_order();
    test_hex();
    test_sm4_padding();
    test_full_operations();
    printf("constant-time check passed\n");
    return 0;
}
