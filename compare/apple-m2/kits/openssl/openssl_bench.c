/*
 * OpenSSL SM2, SM3 and SM4 benchmark in the shared Mac kit format.
 *
 * Build: cc -O2 -I$OSSL/include -o openssl_bench openssl_bench.c $OSSL/lib/libcrypto.a
 * Run:   ./openssl_bench
 * Prints "<name>\t<median_us>\t<min_us>": 7 samples of at least 200 ms after a warm-up.
 * OpenSSL has no SM2 key exchange, so sm2/key_exchange is printed as NA.
 */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SAMPLES 7
#define SAMPLE_US 200000.0
#define WARMUP_US 300000.0

static const unsigned char SM2_ID[] = "1234567812345678";

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

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void run_case(const char *name, bench_fn fn, void *ctx) {
    double end = now_us() + WARMUP_US;
    while (now_us() < end) {
        fn(ctx);
    }
    double samples[SAMPLES];
    for (int s = 0; s < SAMPLES; s++) {
        unsigned long n = 0;
        double start = now_us(), t = start;
        while (t - start < SAMPLE_US) {
            fn(ctx);
            n++;
            t = now_us();
        }
        samples[s] = (t - start) / (double)n;
    }
    qsort(samples, SAMPLES, sizeof(double), cmp_double);
    printf("%s\t%.4f\t%.4f\n", name, samples[SAMPLES / 2], samples[0]);
    fflush(stdout);
}

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
    int n = 0, f = 0;
    if (ctx == NULL || EVP_CipherInit_ex(ctx, EVP_sm4_cbc(), NULL, c->key, c->iv, c->encrypt) != 1 ||
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
    if (md == NULL || pctx == NULL || EVP_PKEY_CTX_set1_id(pctx, SM2_ID, 16) != 1) {
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

static void bench_sm2_sign(void *p) {
    sm2_ctx *c = p;
    EVP_MD_CTX *md = digest_ctx(c->key, 0);
    size_t len = sizeof(c->sig);
    if (EVP_DigestSign(md, c->sig, &len, c->msg, sizeof(c->msg)) != 1) {
        fail("SM2 sign");
    }
    c->sig_len = len;
    free_digest_ctx(md);
}

static void bench_sm2_verify(void *p) {
    sm2_ctx *c = p;
    EVP_MD_CTX *md = digest_ctx(c->key, 1);
    if (EVP_DigestVerify(md, c->sig, c->sig_len, c->msg, sizeof(c->msg)) != 1) {
        fail("SM2 verify");
    }
    free_digest_ctx(md);
}

static void bench_sm2_encrypt(void *p) {
    sm2_ctx *c = p;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(c->key, NULL);
    size_t len = sizeof(c->cipher);
    if (ctx == NULL || EVP_PKEY_encrypt_init(ctx) != 1 ||
        EVP_PKEY_encrypt(ctx, c->cipher, &len, c->plain, sizeof(c->plain)) != 1) {
        fail("SM2 encrypt");
    }
    c->cipher_len = len;
    EVP_PKEY_CTX_free(ctx);
}

static void bench_sm2_decrypt(void *p) {
    sm2_ctx *c = p;
    unsigned char out[256];
    size_t len = sizeof(out);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(c->key, NULL);
    if (ctx == NULL || EVP_PKEY_decrypt_init(ctx) != 1 ||
        EVP_PKEY_decrypt(ctx, out, &len, c->cipher, c->cipher_len) != 1 || len != sizeof(c->plain) ||
        memcmp(out, c->plain, len) != 0) {
        fail("SM2 decrypt");
    }
    EVP_PKEY_CTX_free(ctx);
}

int main(void) {
    fprintf(stderr, "%s\n", OpenSSL_version(OPENSSL_VERSION));
    const size_t max_len = 1024 * 1024 + 32;
    unsigned char *in = malloc(max_len), *out = malloc(max_len), *cipher = malloc(max_len);
    if (in == NULL || out == NULL || cipher == NULL || RAND_bytes(in, (int)max_len) != 1) {
        fail("setup");
    }

    static const size_t sm3_sizes[] = {64, 1024, 1024 * 1024};
    static const char *const sm3_names[] = {"sm3/64B", "sm3/1KB", "sm3/1MB"};
    for (int i = 0; i < 3; i++) {
        sm3_ctx c = {in, sm3_sizes[i]};
        run_case(sm3_names[i], bench_sm3, &c);
    }

    sm4_ctx s;
    memset(&s, 0, sizeof(s));
    if (RAND_bytes(s.key, 16) != 1 || RAND_bytes(s.iv, 16) != 1) {
        fail("SM4 setup");
    }
    run_case("sm4/key_schedule", bench_sm4_key_schedule, &s);
    static const size_t sm4_sizes[] = {16, 1024, 1024 * 1024};
    static const char *const enc_names[] = {"sm4/cbc_encrypt/16B", "sm4/cbc_encrypt/1KB",
                                            "sm4/cbc_encrypt/1MB"};
    static const char *const dec_names[] = {"sm4/cbc_decrypt/16B", "sm4/cbc_decrypt/1KB",
                                            "sm4/cbc_decrypt/1MB"};
    for (int i = 0; i < 3; i++) {
        s.in = in;
        s.out = cipher;
        s.len = sm4_sizes[i];
        s.encrypt = 1;
        run_case(enc_names[i], bench_sm4, &s);
    }
    for (int i = 0; i < 3; i++) {
        s.in = in;
        s.out = cipher;
        s.len = sm4_sizes[i];
        s.encrypt = 1;
        bench_sm4(&s); /* ciphertext of this size, padding included */
        s.in = cipher;
        s.out = out;
        s.len = sm4_sizes[i] + 16;
        s.encrypt = 0;
        run_case(dec_names[i], bench_sm4, &s);
        if (memcmp(out, in, sm4_sizes[i]) != 0) {
            fail("SM4 round trip");
        }
    }

    run_case("sm2/keygen", bench_sm2_keygen, NULL);
    sm2_ctx m;
    memset(&m, 0, sizeof(m));
    m.key = sm2_keygen();
    if (RAND_bytes(m.msg, 32) != 1 || RAND_bytes(m.plain, 32) != 1) {
        fail("SM2 setup");
    }
    run_case("sm2/sign", bench_sm2_sign, &m);
    bench_sm2_sign(&m);
    run_case("sm2/verify", bench_sm2_verify, &m);
    run_case("sm2/encrypt/32B", bench_sm2_encrypt, &m);
    bench_sm2_encrypt(&m);
    run_case("sm2/decrypt/32B", bench_sm2_decrypt, &m);
    printf("sm2/key_exchange\tNA\tNA\n");

    EVP_PKEY_free(m.key);
    free(in);
    free(out);
    free(cipher);
    return 0;
}
