/*
 * OpenSSL SM2, SM3 and SM4 benchmark, for comparison with the SMX implementations.
 *
 * Build: cc -O2 -o openssl_bench openssl_bench.c -lcrypto
 * Run:   taskset -c 6 ./openssl_bench [milliseconds per round] [rounds]
 *
 * Prints one "name  value us/op" line per case. Each case reports the best round.
 * The operations match the SMX benchmarks: SM4 is CBC with PKCS#7 padding, and SM2 signing uses
 * the default user ID with SM3 over a 32-byte message.
 */
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const unsigned char SM2_ID[] = "1234567812345678";
static const size_t SM2_ID_LEN = 16;

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

static void fail(const char *what) {
    fprintf(stderr, "OpenSSL failure in %s\n", what);
    ERR_print_errors_fp(stderr);
    exit(1);
}

typedef void (*bench_fn)(void *ctx);

static void run_case(const char *name, bench_fn fn, void *ctx, double round_ms, int rounds) {
    double best = 1e30;
    for (int r = 0; r < rounds; r++) {
        unsigned long iterations = 0;
        double start = now_us();
        double end = start + round_ms * 1e3;
        double t = start;
        while (t < end) {
            fn(ctx);
            iterations++;
            t = now_us();
        }
        double per_op = (t - start) / (double)iterations;
        if (per_op < best) {
            best = per_op;
        }
    }
    printf("%-28s %14.3f us/op\n", name, best);
    fflush(stdout);
}

/* ---- SM3 ---- */

typedef struct {
    const unsigned char *data;
    size_t len;
} sm3_ctx;

static void bench_sm3(void *p) {
    sm3_ctx *c = p;
    unsigned char out[32];
    unsigned int out_len = 0;
    if (EVP_Digest(c->data, c->len, out, &out_len, EVP_sm3(), NULL) != 1) {
        fail("EVP_Digest");
    }
}

/* ---- SM4 ---- */

typedef struct {
    unsigned char key[16];
    unsigned char iv[16];
    unsigned char *in;
    unsigned char *out;
    size_t len;
    int encrypt;
} sm4_ctx;

static void bench_sm4(void *p) {
    sm4_ctx *c = p;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0;
    int f = 0;
    if (ctx == NULL ||
        EVP_CipherInit_ex(ctx, EVP_sm4_cbc(), NULL, c->key, c->iv, c->encrypt) != 1 ||
        EVP_CipherUpdate(ctx, c->out, &n, c->in, (int)c->len) != 1 ||
        EVP_CipherFinal_ex(ctx, c->out + n, &f) != 1) {
        fail("SM4 CBC");
    }
    EVP_CIPHER_CTX_free(ctx);
}

static void bench_sm4_key_schedule(void *p) {
    sm4_ctx *c = p;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL || EVP_CipherInit_ex(ctx, EVP_sm4_ecb(), NULL, c->key, NULL, 1) != 1) {
        fail("SM4 key schedule");
    }
    EVP_CIPHER_CTX_free(ctx);
}

/* ---- SM2 ---- */

static EVP_PKEY *sm2_keygen(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    EVP_PKEY *key = NULL;
    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_keygen(ctx, &key) != 1) {
        fail("SM2 keygen");
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static void bench_sm2_keygen(void *p) {
    (void)p;
    EVP_PKEY_free(sm2_keygen());
}

typedef struct {
    EVP_PKEY *key;
    unsigned char msg[32];
    unsigned char sig[128];
    size_t sig_len;
    unsigned char plain[32];
    unsigned char cipher[256];
    size_t cipher_len;
} sm2_ctx;

static EVP_MD_CTX *digest_ctx(EVP_PKEY *key, int verify) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(key, NULL);
    if (md == NULL || pctx == NULL || EVP_PKEY_CTX_set1_id(pctx, SM2_ID, SM2_ID_LEN) != 1) {
        fail("SM2 digest context");
    }
    EVP_MD_CTX_set_pkey_ctx(md, pctx);
    int rc = verify ? EVP_DigestVerifyInit(md, NULL, EVP_sm3(), NULL, key)
                    : EVP_DigestSignInit(md, NULL, EVP_sm3(), NULL, key);
    if (rc != 1) {
        fail("SM2 digest init");
    }
    return md;
}

static void free_digest_ctx(EVP_MD_CTX *md) {
    EVP_PKEY_CTX *pctx = EVP_MD_CTX_get_pkey_ctx(md);
    EVP_MD_CTX_free(md);
    EVP_PKEY_CTX_free(pctx);
}

static void sm2_sign_once(sm2_ctx *c) {
    EVP_MD_CTX *md = digest_ctx(c->key, 0);
    size_t len = sizeof(c->sig);
    if (EVP_DigestSign(md, c->sig, &len, c->msg, sizeof(c->msg)) != 1) {
        fail("SM2 sign");
    }
    c->sig_len = len;
    free_digest_ctx(md);
}

static void bench_sm2_sign(void *p) {
    sm2_sign_once(p);
}

static void bench_sm2_verify(void *p) {
    sm2_ctx *c = p;
    EVP_MD_CTX *md = digest_ctx(c->key, 1);
    if (EVP_DigestVerify(md, c->sig, c->sig_len, c->msg, sizeof(c->msg)) != 1) {
        fail("SM2 verify");
    }
    free_digest_ctx(md);
}

static void sm2_encrypt_once(sm2_ctx *c) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(c->key, NULL);
    size_t len = sizeof(c->cipher);
    if (ctx == NULL || EVP_PKEY_encrypt_init(ctx) != 1 ||
        EVP_PKEY_encrypt(ctx, c->cipher, &len, c->plain, sizeof(c->plain)) != 1) {
        fail("SM2 encrypt");
    }
    c->cipher_len = len;
    EVP_PKEY_CTX_free(ctx);
}

static void bench_sm2_encrypt(void *p) {
    sm2_encrypt_once(p);
}

static void bench_sm2_decrypt(void *p) {
    sm2_ctx *c = p;
    unsigned char out[256];
    size_t len = sizeof(out);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(c->key, NULL);
    if (ctx == NULL || EVP_PKEY_decrypt_init(ctx) != 1 ||
        EVP_PKEY_decrypt(ctx, out, &len, c->cipher, c->cipher_len) != 1) {
        fail("SM2 decrypt");
    }
    EVP_PKEY_CTX_free(ctx);
}

int main(int argc, char **argv) {
    double round_ms = argc > 1 ? atof(argv[1]) : 300.0;
    int rounds = argc > 2 ? atoi(argv[2]) : 5;
    if (round_ms <= 0 || rounds <= 0) {
        fprintf(stderr, "usage: %s [milliseconds per round] [rounds]\n", argv[0]);
        return 2;
    }
    printf("%s\n", OpenSSL_version(OPENSSL_VERSION));

    static const size_t sizes[] = {64, 1024, 1024 * 1024};
    static const char *const labels[] = {"64B", "1KB", "1MB"};
    size_t max_len = 1024 * 1024 + 32;
    unsigned char *in = malloc(max_len);
    unsigned char *out = malloc(max_len);
    unsigned char *cipher = malloc(max_len);
    if (in == NULL || out == NULL || cipher == NULL || RAND_bytes(in, (int)max_len) != 1) {
        fail("setup");
    }

    char name[64];
    for (int i = 0; i < 3; i++) {
        sm3_ctx c = {in, sizes[i]};
        snprintf(name, sizeof(name), "SM3 %s", labels[i]);
        run_case(name, bench_sm3, &c, round_ms, rounds);
    }

    sm4_ctx s;
    memset(&s, 0, sizeof(s));
    if (RAND_bytes(s.key, 16) != 1 || RAND_bytes(s.iv, 16) != 1) {
        fail("SM4 setup");
    }
    run_case("SM4 key schedule", bench_sm4_key_schedule, &s, round_ms, rounds);

    static const size_t sm4_sizes[] = {16, 1024, 1024 * 1024};
    static const char *const sm4_labels[] = {"16B", "1KB", "1MB"};
    for (int i = 0; i < 3; i++) {
        s.in = in;
        s.out = cipher;
        s.len = sm4_sizes[i];
        s.encrypt = 1;
        snprintf(name, sizeof(name), "SM4 encrypt %s", sm4_labels[i]);
        run_case(name, bench_sm4, &s, round_ms, rounds);

        /* The ciphertext of the last encrypt is decrypted, padding included. */
        bench_sm4(&s);
        s.in = cipher;
        s.out = out;
        s.len = sm4_sizes[i] + 16;
        s.encrypt = 0;
        snprintf(name, sizeof(name), "SM4 decrypt %s", sm4_labels[i]);
        run_case(name, bench_sm4, &s, round_ms, rounds);
    }

    run_case("SM2 keygen", bench_sm2_keygen, NULL, round_ms, rounds);

    sm2_ctx m;
    memset(&m, 0, sizeof(m));
    m.key = sm2_keygen();
    if (RAND_bytes(m.msg, sizeof(m.msg)) != 1 || RAND_bytes(m.plain, sizeof(m.plain)) != 1) {
        fail("SM2 setup");
    }
    run_case("SM2 sign", bench_sm2_sign, &m, round_ms, rounds);
    sm2_sign_once(&m);
    run_case("SM2 verify", bench_sm2_verify, &m, round_ms, rounds);
    run_case("SM2 encrypt 32B", bench_sm2_encrypt, &m, round_ms, rounds);
    sm2_encrypt_once(&m);
    run_case("SM2 decrypt 32B", bench_sm2_decrypt, &m, round_ms, rounds);

    EVP_PKEY_free(m.key);
    free(in);
    free(out);
    free(cipher);
    return 0;
}
