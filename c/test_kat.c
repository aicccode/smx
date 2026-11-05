/*
 * Known-answer tests. Public API only, so this file also builds and passes
 * against the unmodified baseline, which is what makes the vectors meaningful:
 *   - standards vectors: GB/T 32905 (SM3), GB/T 32907 (SM4), GB/T 32918 (SM2)
 *   - test_kat_vectors.h: outputs captured from the baseline for fixed inputs
 */
#include "smx.h"
#include "test_kat_vectors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COUNT_OF(a) (sizeof(a) / sizeof((a)[0]))

static int passed = 0, failed = 0;

static void check(const char *name, int cond) {
    if (cond) {
        passed++;
    } else {
        printf("  FAIL: %s\n", name);
        failed++;
    }
}

static void check_str(const char *name, const char *got, const char *want) {
    if (strcmp(got, want) == 0) {
        passed++;
    } else {
        printf("  FAIL: %s\n    got:  %s\n    want: %s\n", name, got, want);
        failed++;
    }
}

static void check_big(const char *name, const BigInt256 *got, const char *want) {
    char h[65];
    bigint256_to_hex(got, h);
    check_str(name, h, want);
}

static void check_point(const char *name, const ECPoint *got, const char *want) {
    char h[131];
    ec_point_to_hex_encoded(got, h);
    check_str(name, h, want);
}

/* ---- SM3 ---- */

static void test_sm3_standard(void) {
    static const char abcd16[] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    SM3 h;
    size_t i;

    sm3_init(&h);
    sm3_update(&h, (const uint8_t *)"abc", 3);
    sm3_finish(&h);
    check_str("GB/T 32905 abc", h.hash_hex,
              "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0");

    sm3_update(&h, (const uint8_t *)abcd16, 64); /* finish resets for reuse */
    sm3_finish(&h);
    check_str("GB/T 32905 abcd*16", h.hash_hex,
              "DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732");

    sm3_init(&h);
    for (i = 0; i < 1000000; i++) {
        sm3_update_byte(&h, 'a');
    }
    sm3_finish(&h);
    check_str("SM3 one million a", h.hash_hex,
              "C8AAF89429554029E231941A2ACC0AD61FF2A5ACD8FADD25847A3A732B3B02C3");
}

static void make_pattern(uint8_t *buf, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        buf[i] = (uint8_t)(1 + (i * 131 + (i >> 8)) % 255);
    }
}

static void test_sm3_captured(void) {
    uint8_t *buf = (uint8_t *)malloc(1048576);
    size_t i;
    make_pattern(buf, 1048576);

    for (i = 0; i < COUNT_OF(kat_sm3); i++) {
        size_t len = kat_sm3[i].len;
        SM3 h;
        size_t chunk;
        sm3_init(&h);
        sm3_update(&h, buf, len);
        sm3_finish(&h);
        check_str("SM3 captured", h.hash_hex, kat_sm3[i].hash);

        /* the same digest must come out however the input is split */
        if (len > 70000) {
            continue;
        }
        for (chunk = 1; chunk <= 130; chunk += (chunk < 8 ? 1 : 7)) {
            size_t off = 0;
            sm3_init(&h);
            while (off < len) {
                size_t n = len - off < chunk ? len - off : chunk;
                sm3_update(&h, buf + off, n);
                off += n;
            }
            sm3_finish(&h);
            check_str("SM3 streaming split", h.hash_hex, kat_sm3[i].hash);
        }
        sm3_init(&h);
        for (chunk = 0; chunk < len; chunk++) {
            sm3_update_byte(&h, buf[chunk]);
        }
        sm3_finish(&h);
        check_str("SM3 byte by byte", h.hash_hex, kat_sm3[i].hash);
    }
    free(buf);
}

/* ---- SM4 ---- */

static const uint8_t std_key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                                    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};

/*
 * Raw single-block encryption through the public CBC API. The API takes NUL
 * terminated strings, so a fixed NUL-free block is sent and the IV is chosen to
 * turn it into the wanted input: C1 = E(P xor IV).
 */
static void sm4_raw_block(SM4 *ctx, const uint8_t in[16], uint8_t out[16]) {
    static const char filler[17] =
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";
    char *hex;
    int i;
    for (i = 0; i < 16; i++) {
        ctx->iv[i] = (uint8_t)(in[i] ^ 0x01);
    }
    hex = sm4_encrypt(ctx, filler);
    hex[32] = '\0';
    hex_to_bytes(hex, out, 16);
    free(hex);
}

static void test_sm4_standard(void) {
    SM4 ctx;
    uint8_t block[16];
    uint8_t zero_iv[16] = {0};
    char hex[33];
    int i;

    sm4_init(&ctx);
    sm4_set_key(&ctx, std_key, 16, zero_iv, 16);
    check("SM4 key schedule rk[0]", ctx.rk[0] == 0xF12186F9u);
    check("SM4 key schedule rk[31]", ctx.rk[31] == 0x9124A012u);

    memcpy(block, std_key, 16);
    sm4_raw_block(&ctx, block, block);
    bytes_to_hex(block, 16, hex);
    check_str("GB/T 32907 one block", hex, "681edf34d206965e86b3e94f536e4246");

    memcpy(block, std_key, 16);
    for (i = 0; i < 1000000; i++) {
        sm4_raw_block(&ctx, block, block);
    }
    bytes_to_hex(block, 16, hex);
    check_str("GB/T 32907 1,000,000 iterations", hex, "595298c7c6fd271f0402f804c33d3f66");
}

/*
 * The baseline hashed any key that was not 16 bytes. That path is gone, so these vectors
 * supply what it derived, keeping the captured ciphertext meaningful.
 */
static void derive_old_text_key(const char *text, uint8_t out[16]) {
    size_t len = strlen(text);
    if (len == 16) {
        memcpy(out, text, 16);
    } else {
        SM3 h;
        sm3_init(&h);
        sm3_update(&h, (const uint8_t *)text, len);
        sm3_finish(&h);
        memcpy(out, h.hash_hex, 16);
    }
}

static void test_sm4_captured(void) {
    uint8_t *buf = (uint8_t *)malloc(1048577);
    size_t k;
    make_pattern(buf, 1048577);

    for (k = 0; k < COUNT_OF(kat_sm4); k++) {
        SM4 ctx;
        SM3 h;
        size_t n;
        char *c, *p;
        uint8_t saved;
        uint8_t key[16], iv[16];

        derive_old_text_key(kat_sm4[k].key, key);
        derive_old_text_key(kat_sm4[k].iv, iv);
        sm4_init(&ctx);
        sm4_set_key(&ctx, key, 16, iv, 16);
        sm3_init(&h);
        for (n = 0; n <= 600; n++) {
            saved = buf[n];
            buf[n] = 0;
            c = sm4_encrypt(&ctx, (const char *)buf);
            sm3_update(&h, (const uint8_t *)c, strlen(c));
            p = sm4_decrypt(&ctx, c);
            check("SM4 decrypt returned", p != NULL);
            if (p != NULL) {
                check("SM4 roundtrip by length", strcmp(p, (const char *)buf) == 0);
            }
            free(p);
            free(c);
            buf[n] = saved;
        }
        sm3_finish(&h);
        check_str("SM4 digest of all lengths", h.hash_hex, kat_sm4[k].enc_digest);

        saved = buf[1048576];
        buf[1048576] = 0;
        c = sm4_encrypt(&ctx, (const char *)buf);
        sm3_init(&h);
        sm3_update(&h, (const uint8_t *)c, strlen(c));
        sm3_finish(&h);
        check_str("SM4 digest of 1MB", h.hash_hex, kat_sm4[k].mb_digest);
        p = sm4_decrypt(&ctx, c);
        check("SM4 1MB roundtrip", p != NULL && strcmp(p, (const char *)buf) == 0);
        free(p);
        free(c);
        buf[1048576] = saved;
    }
    free(buf);
}

static void test_sm4_bad_input(void) {
    SM4 ctx;
    char *c, *p;
    size_t last;
    sm4_init(&ctx);
    sm4_set_key(&ctx, std_key, 16, std_key, 16);

    check("SM4 rejects non-block ciphertext", sm4_decrypt(&ctx, "00112233") == NULL);

    check("SM4 rejects empty ciphertext", sm4_decrypt(&ctx, "") == NULL);

    /* flipping the last ciphertext nibble must not crash and must not return the plaintext */
    c = sm4_encrypt(&ctx, "padding oracle probe");
    last = strlen(c) - 1;
    c[last] = (char)(c[last] == '0' ? '1' : '0');
    p = sm4_decrypt(&ctx, c);
    check("SM4 tampered ciphertext", p == NULL || strcmp(p, "padding oracle probe") != 0);
    free(p);
    free(c);
}

/* ---- SM2 ---- */

static void test_sm2_standard(void) {
    /* GB/T 32918.2 / GM/T 0003.2 recommended curve example */
    static const char d_hex[] = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
    static const char pub_hex[] =
        "0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"
        "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13";
    static const char sig_hex[] =
        "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3h"
        "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa";
    /* GB/T 32918.4 example, C1 || C3 || C2 */
    static const char cipher_hex[] =
        "0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73"
        "e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0"
        "59983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd8766"
        "21886ca989ca9c7d58087307ca93092d651efa";
    BigInt256 d = bigint256_from_hex(d_hex);
    ECPoint pub = sm2_get_public_key(&d);
    char *plain;

    check_point("GB/T 32918 public key", &pub,
                "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
                "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13");
    check("GB/T 32918 signature verifies",
          sm2_verify("1234567812345678", sig_hex, "message digest", pub_hex));
    check("GB/T 32918 signature rejects other message",
          !sm2_verify("1234567812345678", sig_hex, "message digesu", pub_hex));
    check("GB/T 32918 signature rejects other id",
          !sm2_verify("1234567812345679", sig_hex, "message digest", pub_hex));

    plain = sm2_decrypt(cipher_hex, d_hex);
    check("GB/T 32918 decrypt returned", plain != NULL);
    if (plain != NULL) {
        check_str("GB/T 32918 decrypt", plain, "encryption standard");
    }
    free(plain);
}

static void test_sm2_captured(void) {
    size_t i;
    for (i = 0; i < COUNT_OF(kat_sm2); i++) {
        char *p, *c, *s;
        char *bad;
        size_t len;

        p = sm2_decrypt(kat_sm2[i].cipher, kat_sm2[i].pri);
        check("SM2 captured decrypt returned", p != NULL);
        if (p != NULL) {
            check_str("SM2 captured decrypt", p, kat_sm2[i].msg);
        }
        free(p);

        check("SM2 captured verify",
              sm2_verify("ALICE123@YAHOO.COM", kat_sm2[i].sig, kat_sm2[i].msg, kat_sm2[i].pub));
        check("SM2 captured verify wrong id",
              !sm2_verify("ALICE123@YAHOO.COM.", kat_sm2[i].sig, kat_sm2[i].msg, kat_sm2[i].pub));

        /* C3 check: any change to the ciphertext must be rejected */
        len = strlen(kat_sm2[i].cipher);
        bad = (char *)malloc(len + 1);
        memcpy(bad, kat_sm2[i].cipher, len + 1);
        bad[len - 1] = (char)(bad[len - 1] == '0' ? '1' : '0');
        p = sm2_decrypt(bad, kat_sm2[i].pri);
        check("SM2 tampered C2 rejected", p == NULL);
        free(p);
        memcpy(bad, kat_sm2[i].cipher, len + 1);
        bad[140] = (char)(bad[140] == '0' ? '1' : '0');
        p = sm2_decrypt(bad, kat_sm2[i].pri);
        check("SM2 tampered C3 rejected", p == NULL);
        free(p);
        memcpy(bad, kat_sm2[i].cipher, len + 1);
        bad[10] = (char)(bad[10] == '0' ? '1' : '0');
        p = sm2_decrypt(bad, kat_sm2[i].pri);
        check("SM2 off-curve C1 rejected", p == NULL);
        free(p);
        free(bad);

        /* fresh randomness, same key */
        c = sm2_encrypt(kat_sm2[i].msg, kat_sm2[i].pub);
        p = sm2_decrypt(c, kat_sm2[i].pri);
        check("SM2 encrypt roundtrip", p != NULL && strcmp(p, kat_sm2[i].msg) == 0);
        check("SM2 ciphertext length", strlen(c) == 130 + 64 + 2 * strlen(kat_sm2[i].msg));
        free(p);
        free(c);

        s = sm2_sign("ALICE123@YAHOO.COM", kat_sm2[i].msg, kat_sm2[i].pri);
        check("SM2 sign verifies",
              sm2_verify("ALICE123@YAHOO.COM", s, kat_sm2[i].msg, kat_sm2[i].pub));
        check("SM2 signature format", strlen(s) == 129 && s[64] == 'h');
        free(s);
    }
}

static void test_sm2_verify_ranges(void) {
    static const char r_ok[] = "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3";
    static const char s_ok[] = "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa";
    static const char n_hex[] = "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123";
    static const char pub[] = "0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"
                              "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13";
    static const char off_curve[] =
        "0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"
        "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD14";
    char sig[140];
    const char *uid = "1234567812345678", *msg = "message digest";

    snprintf(sig, sizeof(sig), "%sh%s", "0", s_ok);
    check("verify rejects r = 0", !sm2_verify(uid, sig, msg, pub));
    snprintf(sig, sizeof(sig), "%sh%s", r_ok, "0");
    check("verify rejects s = 0", !sm2_verify(uid, sig, msg, pub));
    snprintf(sig, sizeof(sig), "%sh%s", n_hex, s_ok);
    check("verify rejects r = n", !sm2_verify(uid, sig, msg, pub));
    snprintf(sig, sizeof(sig), "%sh%s", r_ok, n_hex);
    check("verify rejects s = n", !sm2_verify(uid, sig, msg, pub));
    check("verify rejects missing separator", !sm2_verify(uid, r_ok, msg, pub));
    snprintf(sig, sizeof(sig), "%sh%s", r_ok, s_ok);
    check("verify accepts the good signature", sm2_verify(uid, sig, msg, pub));
    check("verify rejects off-curve key", !sm2_verify(uid, sig, msg, off_curve));
    /* r + s == n must be rejected (t == 0) */
    snprintf(sig, sizeof(sig), "%sh%s",
             "0000000000000000000000000000000000000000000000000000000000000001",
             "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54122");
    check("verify rejects r + s == n", !sm2_verify(uid, sig, msg, pub));
}

static void test_fp_captured(void) {
    size_t i;
    for (i = 0; i < COUNT_OF(kat_fp); i++) {
        FpElement a = fp_from_hex(kat_fp[i].a), b = fp_from_hex(kat_fp[i].b);
        FpElement m = fp_mul(a, b), s = fp_square(a), v = fp_invert(a);
        FpElement ad = fp_add(a, b), su = fp_sub(a, b);
        check_big("fp_mul", &m.value, kat_fp[i].mul);
        check_big("fp_square", &s.value, kat_fp[i].sqr);
        check_big("fp_invert", &v.value, kat_fp[i].inv);
        check_big("fp_add", &ad.value, kat_fp[i].add);
        check_big("fp_sub", &su.value, kat_fp[i].sub);
    }
}

static void test_generic_captured(void) {
    size_t i;
    BigInt256 one = bigint256_one();
    for (i = 0; i < COUNT_OF(kat_generic); i++) {
        BigInt256 a = bigint256_from_hex(kat_generic[i].a);
        BigInt256 b = bigint256_from_hex(kat_generic[i].b);
        BigInt256 m = bigint256_from_hex(kat_generic[i].m);
        BigInt256 e = b, r, ra = a, rb = b;
        e.limbs[3] = 0;
        e.limbs[2] = 0;
        e.limbs[1] &= 0xFF;
        bigint256_mod_mul(&r, &a, &b, &m);
        check_big("bigint256_mod_mul", &r, kat_generic[i].mod_mul);
        bigint256_mod_pow(&r, &a, &e, &m);
        check_big("bigint256_mod_pow", &r, kat_generic[i].mod_pow);
        /*
         * The baseline computed a^(m-2), which is an inverse only for a prime m. Now the true
         * inverse or 0, so the captured value still holds for the two prime moduli.
         */
        bigint256_mod_inverse(&r, &a, &m);
        if (bigint256_compare(&m, &SM2_N) == 0 || bigint256_compare(&m, &SM2_P) == 0) {
            check_big("bigint256_mod_inverse", &r, kat_generic[i].mod_inv);
        }
        if (!bigint256_is_zero(&m)) {
            bigint256_mod_mul(&ra, &a, &one, &m);
            bigint256_mod_mul(&rb, &b, &one, &m);
        }
        bigint256_mod_add(&r, &ra, &rb, &m);
        check_big("bigint256_mod_add", &r, kat_generic[i].mod_add);
        bigint256_mod_sub(&r, &ra, &rb, &m);
        check_big("bigint256_mod_sub", &r, kat_generic[i].mod_sub);
    }
}

static void test_points_captured(void) {
    size_t i;
    for (i = 0; i < COUNT_OF(kat_pub); i++) {
        BigInt256 k = bigint256_from_hex(kat_pub[i].k);
        ECPoint p = sm2_get_public_key(&k);
        ECPoint q = ec_point_multiply(ec_point_generator(), &k);
        BigInt256 n_minus_1 = SM2_N;
        n_minus_1.limbs[0] -= 1;
        /* sm2_get_public_key now refuses what is not a private key: 0 and >= n - 1 */
        if (bigint256_is_zero(&k) || bigint256_compare(&k, &n_minus_1) >= 0) {
            check("public key of an invalid private key", p.infinity);
        } else {
            check_point("d*G", &p, kat_pub[i].pub);
        }
        check_point("ec_point_multiply(G)", &q, kat_pub[i].pub);
    }
    for (i = 0; i < COUNT_OF(kat_mul); i++) {
        BigInt256 a = bigint256_from_hex(kat_mul[i].a);
        BigInt256 k = bigint256_from_hex(kat_mul[i].k);
        ECPoint base = sm2_get_public_key(&a);
        ECPoint m = ec_point_multiply(base, &k);
        ECPoint s = ec_point_add(base, m);
        check_point("k*P", &m, kat_mul[i].mul);
        check_point("P + k*P", &s, kat_mul[i].sum);
    }
}

static void test_key_exchange_captured(void) {
    const char *ida = "ALICE123@YAHOO.COM", *idb = "BILL456@YAHOO.COM";
    size_t i;
    for (i = 0; i < COUNT_OF(kat_kx); i++) {
        BigInt256 da = bigint256_from_hex(kat_kx[i].da), db = bigint256_from_hex(kat_kx[i].db);
        BigInt256 ra = bigint256_from_hex(kat_kx[i].ra), rb = bigint256_from_hex(kat_kx[i].rb);
        ECPoint pa = sm2_get_public_key(&da), pb = sm2_get_public_key(&db);
        ECPoint ra_p = sm2_get_public_key(&ra), rb_p = sm2_get_public_key(&rb);
        SM2KeySwapParams b, a;
        uint8_t sb[32], sa[32];
        char za[65], zb[65];
        int len = kat_kx[i].len;

        b = sm2_get_sb(len, pa, ra_p, pb, &db, rb_p, &rb, ida, idb);
        check("KX B success", b.success);
        hex_to_bytes(b.sb, sb, 32);
        a = sm2_get_sa(len, pb, rb_p, pa, &da, ra_p, &ra, ida, idb, sb, 32);
        check("KX A success", a.success);
        check_str("KX Ka", a.ka, kat_kx[i].ka);
        check_str("KX Kb", b.kb, kat_kx[i].kb);
        check_str("KX Sa", a.sa, kat_kx[i].sa);
        check_str("KX Sb", b.sb, kat_kx[i].sb);
        bytes_to_hex(b.za, 32, za);
        bytes_to_hex(b.zb, 32, zb);
        check_str("KX Za", za, kat_kx[i].za);
        check_str("KX Zb", zb, kat_kx[i].zb);
        check_point("KX V", &b.v, kat_kx[i].v);
        hex_to_bytes(a.sa, sa, 32);
        check("KX check Sa", sm2_check_sa(b.v, b.za, b.zb, ra_p, rb_p, sa, 32));
        sa[0] ^= 1;
        check("KX check bad Sa", !sm2_check_sa(b.v, b.za, b.zb, ra_p, rb_p, sa, 32));
        sb[31] ^= 1;
        a = sm2_get_sa(len, pb, rb_p, pa, &da, ra_p, &ra, ida, idb, sb, 32);
        check("KX bad Sb rejected", !a.success);
    }
}

int main(void) {
    printf("=== SM3 known answers ===\n");
    test_sm3_standard();
    test_sm3_captured();
    printf("=== SM4 known answers ===\n");
    test_sm4_standard();
    test_sm4_captured();
    test_sm4_bad_input();
    printf("=== SM2 known answers ===\n");
    test_sm2_standard();
    test_fp_captured();
    test_generic_captured();
    test_points_captured();
    test_sm2_captured();
    test_sm2_verify_ranges();
    test_key_exchange_captured();

    printf("\n=== KAT results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
