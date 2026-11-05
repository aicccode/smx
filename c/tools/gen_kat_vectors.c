/*
 * Captures known-answer vectors from a given revision of the library into a C
 * header consumed by test_kat.c. The committed test_kat_vectors.h was produced
 * by building this file against the baseline at commit 3397c6d, *before* any
 * optimization, so the vectors pin baseline behaviour. Do not regenerate it
 * from a modified library without a reason you can explain.
 *
 *   gcc -std=c99 -O2 -Ibaseline tools/gen_kat_vectors.c baseline/{bigint256,sm3,sm4,sm2}.c \
 *       -o gen && ./gen > test_kat_vectors.h
 */
#include "smx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t rng_state = 0x243F6A8885A308D3ULL;

static uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static BigInt256 rng_big(void) {
    BigInt256 r;
    int i;
    for (i = 0; i < 4; i++) {
        r.limbs[i] = rng_next();
    }
    return r;
}

static const char *const edge_hex[] = {
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "0000000000000000000000000000000000000000000000000000000000000002",
    "00000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFF00000000000000000000000000000000000000000000000000000000",
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFE", /* p-1 */
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", /* p */
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122", /* n-1 */
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", /* n */
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54124", /* n+1 */
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", /* 2^256-1 */
    "8000000000000000000000000000000000000000000000000000000000000000",
    "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
};
#define EDGE_COUNT ((int)(sizeof(edge_hex) / sizeof(edge_hex[0])))

static void print_big(const BigInt256 *a) {
    char h[65];
    bigint256_to_hex(a, h);
    printf("\"%s\"", h);
}

static void print_point(const ECPoint *p) {
    char h[131];
    ec_point_to_hex_encoded(p, h);
    printf("\"%s\"", h);
}

static BigInt256 sample(int i) {
    return i < EDGE_COUNT ? bigint256_from_hex(edge_hex[i]) : rng_big();
}

static void gen_fp(void) {
    int i;
    printf(
        "static const struct { const char *a, *b, *mul, *sqr, *inv, *add, *sub; } kat_fp[] = {\n");
    for (i = 0; i < EDGE_COUNT + 16; i++) {
        int j = (i * 5 + 3) % EDGE_COUNT;
        FpElement a = fp_new(sample(i));
        FpElement b = fp_new(i < EDGE_COUNT ? bigint256_from_hex(edge_hex[j]) : rng_big());
        FpElement m = fp_mul(a, b), s = fp_square(a), v = fp_invert(a);
        FpElement ad = fp_add(a, b), su = fp_sub(a, b);
        printf("    {");
        print_big(&a.value);
        printf(", ");
        print_big(&b.value);
        printf(",\n     ");
        print_big(&m.value);
        printf(", ");
        print_big(&s.value);
        printf(",\n     ");
        print_big(&v.value);
        printf(", ");
        print_big(&ad.value);
        printf(",\n     ");
        print_big(&su.value);
        printf("},\n");
    }
    printf("};\n\n");
}

static void gen_generic(void) {
    int i;
    static const char *const moduli[] = {
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "8000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000001000000000000000000000000000000FF",
        "0000000000000000000000000000000000000000000000010000000000000000",
        "00000000000000000000000000000000000000000000000000000000FFFFFFFB",
        "0000000000000000000000000000000000000000000000000000000000010001",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000000",
    };
    int moduli_count = (int)(sizeof(moduli) / sizeof(moduli[0]));
    printf("static const struct { const char *a, *b, *m, *mod_mul, *mod_pow, *mod_inv, *mod_add, "
           "*mod_sub; } kat_generic[] = {\n");
    for (i = 0; i < moduli_count * 5; i++) {
        BigInt256 m = bigint256_from_hex(moduli[i % moduli_count]);
        BigInt256 a = sample(i), b = rng_big();
        BigInt256 mm, mp, mi, ma, ms, e = b;
        BigInt256 ra = a, rb = b;
        e.limbs[3] = 0;
        e.limbs[2] = 0;
        e.limbs[1] &= 0xFF;
        bigint256_mod_mul(&mm, &a, &b, &m);
        bigint256_mod_pow(&mp, &a, &e, &m);
        /* m-2 underflows for m < 2 in the baseline; that is still deterministic */
        bigint256_mod_inverse(&mi, &a, &m);
        /* mod_add/mod_sub are only specified for reduced operands */
        if (!bigint256_is_zero(&m)) {
            bigint256_mod_mul(&ra, &a, &(BigInt256){{1, 0, 0, 0}}, &m);
            bigint256_mod_mul(&rb, &b, &(BigInt256){{1, 0, 0, 0}}, &m);
        }
        bigint256_mod_add(&ma, &ra, &rb, &m);
        bigint256_mod_sub(&ms, &ra, &rb, &m);
        printf("    {");
        print_big(&a);
        printf(", ");
        print_big(&b);
        printf(", \"%s\",\n     ", moduli[i % moduli_count]);
        print_big(&mm);
        printf(", ");
        print_big(&mp);
        printf(",\n     ");
        print_big(&mi);
        printf(", ");
        print_big(&ma);
        printf(",\n     ");
        print_big(&ms);
        printf("},\n");
    }
    printf("};\n\n");
}

static void gen_points(void) {
    int i;
    printf("static const struct { const char *k, *pub; } kat_pub[] = {\n");
    for (i = 0; i < EDGE_COUNT + 16; i++) {
        BigInt256 k = sample(i);
        ECPoint p = sm2_get_public_key(&k);
        printf("    {");
        print_big(&k);
        printf(",\n     ");
        print_point(&p);
        printf("},\n");
    }
    printf("};\n\n");

    printf("static const struct { const char *a, *k, *mul, *sum; } kat_mul[] = {\n");
    for (i = 0; i < EDGE_COUNT + 16; i++) {
        BigInt256 a = rng_big();
        BigInt256 k = sample(i);
        ECPoint base = sm2_get_public_key(&a);
        ECPoint m = ec_point_multiply(base, &k);
        ECPoint s = ec_point_add(base, m);
        printf("    {");
        print_big(&a);
        printf(", ");
        print_big(&k);
        printf(",\n     ");
        print_point(&m);
        printf(",\n     ");
        print_point(&s);
        printf("},\n");
    }
    printf("};\n\n");
}

static void gen_sm2(void) {
    int i;
    static const char *const messages[] = {
        "a",
        "encryption standard",
        "\xe5\x9b\xbd\xe5\xaf\x86SM2\xe7\xae\x97\xe6\xb3\x95",
        "0123456789abcdef0123456789abcde",
        "0123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdef0",
        "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the "
        "lazy dog. The quick brown fox jumps over the lazy dog.",
    };
    int count = (int)(sizeof(messages) / sizeof(messages[0]));
    printf("static const struct { const char *pri, *pub, *msg, *cipher, *sig; } kat_sm2[] = {\n");
    for (i = 0; i < count; i++) {
        char pri[65], pub[131];
        char *c, *s;
        const char *m = messages[i];
        BigInt256 d = rng_big();
        ECPoint p;
        int j;
        while (bigint256_compare(&d, &SM2_N) >= 0) {
            d = rng_big();
        }
        p = sm2_get_public_key(&d);
        bigint256_to_hex(&d, pri);
        ec_point_to_hex_encoded(&p, pub);
        c = sm2_encrypt(m, pub);
        s = sm2_sign("ALICE123@YAHOO.COM", m, pri);
        printf("    {\"%s\",\n     \"%s\",\n     \"", pri, pub);
        for (j = 0; m[j]; j++) {
            printf("\\x%02x", (unsigned)(unsigned char)m[j]);
        }
        printf("\",\n     \"%s\",\n     \"%s\"},\n", c, s);
        free(c);
        free(s);
    }
    printf("};\n\n");
}

static void gen_kx(void) {
    int i;
    static const int lens[] = {1, 16, 31, 32, 33, 64, 200, 256};
    printf("static const struct { int len; const char *da, *db, *ra, *rb, *ka, *kb, *sa, *sb, "
           "*za, *zb, *v; } kat_kx[] = {\n");
    for (i = 0; i < 8; i++) {
        BigInt256 da = rng_big(), db = rng_big(), ra = rng_big(), rb = rng_big();
        const char *ida = "ALICE123@YAHOO.COM", *idb = "BILL456@YAHOO.COM";
        ECPoint pa, pb, ra_p, rb_p;
        SM2KeySwapParams b, a;
        uint8_t sb[32];
        char za[65], zb[65], v[131];
        da.limbs[3] >>= 1;
        db.limbs[3] >>= 1;
        ra.limbs[3] >>= 1;
        rb.limbs[3] >>= 1;
        pa = sm2_get_public_key(&da);
        pb = sm2_get_public_key(&db);
        ra_p = sm2_get_public_key(&ra);
        rb_p = sm2_get_public_key(&rb);
        b = sm2_get_sb(lens[i], pa, ra_p, pb, &db, rb_p, &rb, ida, idb);
        hex_to_bytes(b.sb, sb, 32);
        a = sm2_get_sa(lens[i], pb, rb_p, pa, &da, ra_p, &ra, ida, idb, sb, 32);
        bytes_to_hex(b.za, 32, za);
        bytes_to_hex(b.zb, 32, zb);
        ec_point_to_hex_encoded(&b.v, v);
        printf("    {%d, ", lens[i]);
        print_big(&da);
        printf(", ");
        print_big(&db);
        printf(",\n     ");
        print_big(&ra);
        printf(", ");
        print_big(&rb);
        printf(",\n     \"%s\",\n     \"%s\",\n     \"%s\",\n     \"%s\",\n     \"%s\",\n"
               "     \"%s\",\n     \"%s\"},\n",
               a.ka, b.kb, a.sa, b.sb, za, zb, v);
    }
    printf("};\n\n");
}

static void make_pattern(uint8_t *buf, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        buf[i] = (uint8_t)(1 + (i * 131 + (i >> 8)) % 255); /* never NUL */
    }
}

static void gen_sm3(void) {
    static const size_t lens[] = {0,   1,   3,   55,  56,  57,  63,   64,   65,    119,
                                  120, 127, 128, 129, 255, 256, 1000, 4096, 65537, 1048576};
    int count = (int)(sizeof(lens) / sizeof(lens[0]));
    uint8_t *buf = (uint8_t *)malloc(1048576);
    int i;
    make_pattern(buf, 1048576);
    printf("static const struct { size_t len; const char *hash; } kat_sm3[] = {\n");
    for (i = 0; i < count; i++) {
        SM3 h;
        sm3_init(&h);
        sm3_update(&h, buf, lens[i]);
        sm3_finish(&h);
        printf("    {%lu, \"%s\"},\n", (unsigned long)lens[i], h.hash_hex);
    }
    printf("};\n\n");
    free(buf);
}

/*
 * SM3 of the concatenated hex outputs for every plaintext length up to 600,
 * which exercises each multi-block boundary, for 16-byte and hashed keys.
 */
static void gen_sm4(void) {
    uint8_t *buf = (uint8_t *)malloc(1048577);
    static const char *const keys[] = {"0123456789abcdef", "this is the key"};
    static const char *const ivs[] = {"fedcba9876543210", "this is the iv"};
    int k;
    make_pattern(buf, 1048577);
    printf(
        "static const struct { const char *key, *iv, *enc_digest, *mb_digest; } kat_sm4[] = {\n");
    for (k = 0; k < 2; k++) {
        SM4 ctx;
        SM3 h;
        size_t n;
        char *c;
        char saved;
        sm4_init(&ctx);
        sm4_set_key(&ctx, (const uint8_t *)keys[k], strlen(keys[k]), (const uint8_t *)ivs[k],
                    strlen(ivs[k]));
        sm3_init(&h);
        for (n = 0; n <= 600; n++) {
            saved = (char)buf[n];
            buf[n] = 0;
            c = sm4_encrypt(&ctx, (const char *)buf);
            sm3_update(&h, (const uint8_t *)c, strlen(c));
            free(c);
            buf[n] = (uint8_t)saved;
        }
        sm3_finish(&h);
        printf("    {\"%s\", \"%s\",\n     \"%s\",\n", keys[k], ivs[k], h.hash_hex);
        saved = (char)buf[1048576];
        buf[1048576] = 0;
        c = sm4_encrypt(&ctx, (const char *)buf);
        buf[1048576] = (uint8_t)saved;
        sm3_init(&h);
        sm3_update(&h, (const uint8_t *)c, strlen(c));
        sm3_finish(&h);
        printf("     \"%s\"},\n", h.hash_hex);
        free(c);
    }
    printf("};\n\n");
    free(buf);
}

int main(void) {
    printf("/* Generated by tools/gen_kat_vectors.c against the baseline (commit 3397c6d). */\n");
    printf("/* clang-format off */\n\n");
    gen_fp();
    gen_generic();
    gen_points();
    gen_sm2();
    gen_kx();
    gen_sm3();
    gen_sm4();
    printf("/* clang-format on */\n");
    return 0;
}
