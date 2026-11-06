/*
 * SMX C benchmark for the Mac comparison kit. Uses only API present, with the same
 * signatures, at both commit 3397c6d and HEAD, so one program serves both sides.
 *
 * Prints, per operation: name, median and minimum microseconds per operation over 7 timed
 * samples of at least 200 ms each, after one untimed warm-up sample.
 */
#define _POSIX_C_SOURCE 199309L

#include "smx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SAMPLES 7
#define MIN_SAMPLE_SECONDS 0.2
#define USER_ID "1234567812345678"

static volatile size_t sink;

typedef void (*Op)(void *arg);

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static double sample(Op op, void *arg) {
    long n = 0;
    double start = now(), elapsed;
    do {
        op(arg);
        n++;
        elapsed = now() - start;
    } while (elapsed < MIN_SAMPLE_SECONDS);
    return elapsed / (double)n * 1e6;
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static void run(const char *name, Op op, void *arg) {
    double s[SAMPLES];
    int i;
    (void)sample(op, arg); /* warm-up: caches, branch predictors, page faults */
    for (i = 0; i < SAMPLES; i++) {
        s[i] = sample(op, arg);
    }
    qsort(s, SAMPLES, sizeof(double), cmp_double);
    printf("%s\t%.3f\t%.3f\n", name, s[SAMPLES / 2], s[0]);
    fflush(stdout);
}

static void fail(const char *what) {
    fprintf(stderr, "macbench: check failed: %s\n", what);
    exit(1);
}

/* Printable, NUL-free text: the string APIs on both sides stop at a NUL. */
static char *text(size_t n) {
    char *t = (char *)malloc(n + 1);
    size_t i;
    for (i = 0; i < n; i++) {
        t[i] = (char)('a' + (i * 7 + i / 26) % 26);
    }
    t[n] = '\0';
    return t;
}

/* ---- SM3 ---- */

typedef struct {
    const uint8_t *data;
    size_t len;
} Sm3Arg;

static void op_sm3(void *arg) {
    const Sm3Arg *a = (const Sm3Arg *)arg;
    SM3 h;
    sm3_init(&h);
    sm3_update(&h, a->data, a->len);
    sm3_finish(&h);
    sink += h.hash_bytes[0];
}

/* ---- SM4 ---- */

static const uint8_t KEY[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                                0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
static const uint8_t IV[16] = {0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
                               0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01};

typedef struct {
    SM4 *ctx;
    const char *input;
} Sm4Arg;

static void op_sm4_key(void *arg) {
    SM4 *ctx = (SM4 *)arg;
    sm4_set_key(ctx, KEY, 16, IV, 16);
    sink += ctx->rk[31];
}

static void op_sm4_encrypt(void *arg) {
    const Sm4Arg *a = (const Sm4Arg *)arg;
    char *c = sm4_encrypt(a->ctx, a->input);
    sink += (size_t)c[0];
    free(c);
}

static void op_sm4_decrypt(void *arg) {
    const Sm4Arg *a = (const Sm4Arg *)arg;
    char *p = sm4_decrypt(a->ctx, a->input);
    sink += (size_t)p[0];
    free(p);
}

/* ---- SM2 ---- */

typedef struct {
    char pri[65], pub[131];
    char *msg;
    char *sig;
    char *cipher;
} Sm2Arg;

static void op_keygen(void *arg) {
    char pri[65], pub[131];
    (void)arg;
    sm2_gen_keypair(pri, pub);
    sink += (size_t)pub[2];
}

static void op_sign(void *arg) {
    const Sm2Arg *a = (const Sm2Arg *)arg;
    char *s = sm2_sign(USER_ID, a->msg, a->pri);
    sink += (size_t)s[0];
    free(s);
}

static void op_verify(void *arg) {
    const Sm2Arg *a = (const Sm2Arg *)arg;
    sink += (size_t)sm2_verify(USER_ID, a->sig, a->msg, a->pub);
}

static void op_encrypt(void *arg) {
    const Sm2Arg *a = (const Sm2Arg *)arg;
    char *c = sm2_encrypt(a->msg, a->pub);
    sink += (size_t)c[0];
    free(c);
}

static void op_decrypt(void *arg) {
    const Sm2Arg *a = (const Sm2Arg *)arg;
    char *p = sm2_decrypt(a->cipher, a->pri);
    sink += (size_t)p[0];
    free(p);
}

typedef struct {
    BigInt256 da, db;
    ECPoint pa, pb;
} KxArg;

/*
 * One complete exchange: fresh ephemeral keys on both sides, B's value and Sb, A's key, Sb
 * check and Sa, then B's check of Sa. Returns 1 if both sides agree.
 */
static int key_exchange(const KxArg *a) {
    char ra_hex[65], ra_pub_hex[131], rb_hex[65], rb_pub_hex[131];
    BigInt256 ra, rb;
    ECPoint ra_pub, rb_pub;
    SM2KeySwapParams b, r;
    uint8_t sb[32], sa[32];

    sm2_gen_keypair(ra_hex, ra_pub_hex);
    sm2_gen_keypair(rb_hex, rb_pub_hex);
    ra = bigint256_from_hex(ra_hex);
    rb = bigint256_from_hex(rb_hex);
    ra_pub = ec_point_from_hex_encoded(ra_pub_hex);
    rb_pub = ec_point_from_hex_encoded(rb_pub_hex);

    b = sm2_get_sb(16, a->pa, ra_pub, a->pb, &a->db, rb_pub, &rb, USER_ID, USER_ID);
    hex_to_bytes(b.sb, sb, 32);
    r = sm2_get_sa(16, a->pb, rb_pub, a->pa, &a->da, ra_pub, &ra, USER_ID, USER_ID, sb, 32);
    hex_to_bytes(r.sa, sa, 32);
    return b.success && r.success && strcmp(r.ka, b.kb) == 0 &&
           sm2_check_sa(b.v, b.za, b.zb, ra_pub, rb_pub, sa, 32);
}

static void op_key_exchange(void *arg) {
    sink += (size_t)key_exchange((const KxArg *)arg);
}

int main(void) {
    static const size_t sm3_sizes[3] = {64, 1024, 1048576};
    static const char *const sm3_names[3] = {"sm3/64B", "sm3/1KB", "sm3/1MB"};
    static const size_t sm4_sizes[3] = {16, 1024, 1048576};
    static const char *const enc_names[3] = {"sm4/cbc_encrypt/16B", "sm4/cbc_encrypt/1KB",
                                             "sm4/cbc_encrypt/1MB"};
    static const char *const dec_names[3] = {"sm4/cbc_decrypt/16B", "sm4/cbc_decrypt/1KB",
                                             "sm4/cbc_decrypt/1MB"};
    char *ciphers[3], *plains[3];
    SM4 ctx;
    Sm2Arg s2;
    KxArg kx;
    char pri[65], pub[131];
    int i;

    /* ---- every correctness check comes first, outside the timing ---- */
    sm4_init(&ctx);
    sm4_set_key(&ctx, KEY, 16, IV, 16);
    for (i = 0; i < 3; i++) {
        char *back;
        plains[i] = text(sm4_sizes[i]);
        ciphers[i] = sm4_encrypt(&ctx, plains[i]);
        if (ciphers[i] == NULL || strlen(ciphers[i]) != (sm4_sizes[i] / 16 + 1) * 32) {
            fail("SM4 ciphertext length");
        }
        back = sm4_decrypt(&ctx, ciphers[i]);
        if (back == NULL || strcmp(back, plains[i]) != 0) {
            fail("SM4 round trip");
        }
        free(back);
    }
    {
        /* the GB/T 32905 vector */
        SM3 h;
        sm3_init(&h);
        sm3_update(&h, (const uint8_t *)"abc", 3);
        sm3_finish(&h);
        if (strcmp(h.hash_hex,
                   "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0") != 0) {
            fail("SM3 vector");
        }
    }

    sm2_gen_keypair(s2.pri, s2.pub);
    s2.msg = text(32);
    s2.sig = sm2_sign(USER_ID, s2.msg, s2.pri);
    if (s2.sig == NULL || !sm2_verify(USER_ID, s2.sig, s2.msg, s2.pub)) {
        fail("SM2 signature verifies");
    }
    if (sm2_verify(USER_ID, s2.sig, "a different message of 32 bytes", s2.pub)) {
        fail("SM2 signature rejects another message");
    }
    s2.cipher = sm2_encrypt(s2.msg, s2.pub);
    {
        char *back = sm2_decrypt(s2.cipher, s2.pri);
        if (back == NULL || strcmp(back, s2.msg) != 0) {
            fail("SM2 decrypt round trip");
        }
        free(back);
    }

    sm2_gen_keypair(pri, pub);
    kx.da = bigint256_from_hex(pri);
    kx.pa = ec_point_from_hex_encoded(pub);
    sm2_gen_keypair(pri, pub);
    kx.db = bigint256_from_hex(pri);
    kx.pb = ec_point_from_hex_encoded(pub);
    if (!key_exchange(&kx)) {
        fail("SM2 key exchange agrees");
    }

    /* ---- timed ---- */
    for (i = 0; i < 3; i++) {
        Sm3Arg a;
        a.data = (const uint8_t *)plains[i];
        a.len = sm3_sizes[i];
        run(sm3_names[i], op_sm3, &a);
    }
    run("sm4/key_schedule", op_sm4_key, &ctx);
    sm4_set_key(&ctx, KEY, 16, IV, 16);
    for (i = 0; i < 3; i++) {
        Sm4Arg a;
        a.ctx = &ctx;
        a.input = plains[i];
        run(enc_names[i], op_sm4_encrypt, &a);
    }
    for (i = 0; i < 3; i++) {
        Sm4Arg a;
        a.ctx = &ctx;
        a.input = ciphers[i];
        run(dec_names[i], op_sm4_decrypt, &a);
    }
    run("sm2/keygen", op_keygen, NULL);
    run("sm2/sign", op_sign, &s2);
    run("sm2/verify", op_verify, &s2);
    run("sm2/encrypt/32B", op_encrypt, &s2);
    run("sm2/decrypt/32B", op_decrypt, &s2);
    run("sm2/key_exchange", op_key_exchange, &kx);

    return sink == (size_t)-1 ? 2 : 0;
}
