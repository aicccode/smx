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
#include "sm9.c"
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

/*
 * SM9 with every secret poisoned: master keys, user private keys (G1 and G2, whose subgroup check
 * may only branch on validity), r, and everything derived from them. The stream mode only: the
 * SM4 mode uses this branch's table SM4, which is not constant time.
 */
static void test_sm9(void) {
    static const char mpub_s[] = "049f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c4"
                                 "0829dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea"
                                 "5e3269850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0"
                                 "ef1c2541e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05f"
                                 "b4e3216d";
    static const char mpub_e[] = "04787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a8"
                                 "92ff769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c"
                                 "57a7b1";
    char ks[65] = "000130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f4";
    char ke[65] = "0001edee3778f441f8dea3d9fa0acc4e07ee36c93f9a08618af4ad85cede1c22";
    char ds[131], de[259], de_a[259], sig[195], pub[259], key[65], c[131];
    char ra[65], rb[65], big_ra[131], big_rb[131];
    SM9ExchangeResult b, a;
    char *ct;
    uint8_t *pt;

    SECRET(ks, 64);
    SECRET(ke, 64);
    sm9_sign_master_public_key(ks, pub);
    sm9_enc_master_public_key(ke, pub);
    sm9_gen_sign_user_key(ks, "Alice", 1, ds);
    sm9_gen_enc_user_key(ke, "Bob", 3, de);
    sm9_gen_enc_user_key(ke, "Alice", 2, de_a);
    PUBLIC(ds, sizeof(ds));
    PUBLIC(de, sizeof(de));
    PUBLIC(de_a, sizeof(de_a));
    SECRET(ds, 130);
    SECRET(de, 258);
    SECRET(de_a, 258);

    if (!sm9_sign("Chinese IBS standard", ds, mpub_s, sig)) {
        printf("SM9 sign failed\n");
    }
    ct = sm9_encrypt("Chinese IBE standard", "Bob", mpub_e, 3, SM9_MODE_STREAM);
    PUBLIC(ct, ct != NULL ? strlen(ct) : 0);
    pt = sm9_decrypt_bytes(ct, "Bob", de, SM9_MODE_STREAM, NULL);
    if (pt == NULL) {
        printf("SM9 decrypt failed\n");
    }
    free(pt);
    free(ct);
    if (!sm9_encapsulate("Bob", mpub_e, 32, 3, key, c)) {
        printf("SM9 encapsulate failed\n");
    }
    PUBLIC(c, sizeof(c));
    sm9_decapsulate(c, "Bob", de, 32, key);

    sm9_gen_enc_user_key(ke, "Bob", 2, de);
    PUBLIC(de, sizeof(de));
    SECRET(de, 258);
    sm9_exchange_init("Bob", mpub_e, 2, ra, big_ra);
    sm9_exchange_init("Alice", mpub_e, 2, rb, big_rb);
    PUBLIC(big_ra, sizeof(big_ra));
    PUBLIC(big_rb, sizeof(big_rb));
    b = sm9_exchange_respond(16, "Alice", "Bob", mpub_e, de, rb, big_rb, big_ra);
    PUBLIC(&b, sizeof(b));
    a = sm9_exchange_confirm(16, "Alice", "Bob", mpub_e, de_a, ra, big_ra, big_rb, b.s_b);
    PUBLIC(&a, sizeof(a));
    if (!a.success || !sm9_exchange_check(b.s_2, a.s_a)) {
        printf("SM9 key exchange failed\n");
    }
    sm9_exchange_result_free(&a);
    sm9_exchange_result_free(&b);
}

int main(void) {
    test_scalar_mult();
    test_field_and_order();
    test_hex();
    test_sm4_padding();
    test_full_operations();
    test_sm9();
    printf("constant-time check passed\n");
    return 0;
}
