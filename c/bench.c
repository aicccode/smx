/*
 * SMX C benchmark. Uses only the public API in smx.h so the same file builds
 * against any revision of the library.
 *
 *   make bench && taskset -c 2 ./bench [min_ms_per_case] [repeats]
 *
 * Each case runs for at least min_ms milliseconds, `repeats` times; the best
 * run is reported, which is the least contaminated by other load.
 */
#define _POSIX_C_SOURCE 199309L

#include "smx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double min_seconds = 0.2;
static int repeats = 3;
static volatile size_t sink;

typedef void (*BenchFn)(void *arg);

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* Returns the best observed time for one call, in seconds. */
static double measure(BenchFn fn, void *arg) {
    double best = 1e30;
    int r;
    for (r = 0; r < repeats; r++) {
        long iterations = 0;
        double start = now_seconds();
        double elapsed;
        do {
            fn(arg);
            iterations++;
            elapsed = now_seconds() - start;
        } while (elapsed < min_seconds);
        if (elapsed / (double)iterations < best) {
            best = elapsed / (double)iterations;
        }
    }
    return best;
}

static void report_ops(const char *name, BenchFn fn, void *arg) {
    double t = measure(fn, arg);
    printf("%-24s %12.2f us/op %14.0f ops/s\n", name, t * 1e6, 1.0 / t);
    fflush(stdout);
}

static void report_bytes(const char *name, BenchFn fn, void *arg, size_t n) {
    double t = measure(fn, arg);
    printf("%-24s %12.2f us/op %11.1f MB/s\n", name, t * 1e6, (double)n / t / 1e6);
    fflush(stdout);
}

/* ---- SM3 ---- */

typedef struct {
    const uint8_t *data;
    size_t len;
} Sm3Arg;

static void bench_sm3(void *arg) {
    const Sm3Arg *a = (const Sm3Arg *)arg;
    SM3 ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, a->data, a->len);
    sm3_finish(&ctx);
    sink += ctx.hash_bytes[0];
}

/* ---- SM4 ---- */

static const uint8_t sm4_key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
static const uint8_t sm4_iv[16] = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

typedef struct {
    SM4 *ctx;
    const char *text;
} Sm4Arg;

static void bench_sm4_enc(void *arg) {
    const Sm4Arg *a = (const Sm4Arg *)arg;
    char *out = sm4_encrypt(a->ctx, a->text);
    sink += (size_t)out[0];
    free(out);
}

static void bench_sm4_dec(void *arg) {
    const Sm4Arg *a = (const Sm4Arg *)arg;
    char *out = sm4_decrypt(a->ctx, a->text);
    sink += (size_t)out[0];
    free(out);
}

static void bench_sm4_key(void *arg) {
    SM4 *ctx = (SM4 *)arg;
    sm4_set_key(ctx, sm4_key, 16, sm4_iv, 16);
    sink += ctx->rk[31];
}

/* ---- SM2 ---- */

#define USER_ID "ALICE123@YAHOO.COM"
#define MESSAGE "encryption standard"

typedef struct {
    char pri[65], pub[131];
    char *sig;
    char *cipher;
    BigInt256 d;
} Sm2Arg;

static void bench_keygen(void *arg) {
    char pri[65], pub[131];
    (void)arg;
    sm2_gen_keypair(pri, pub);
    sink += (size_t)pub[2];
}

static void bench_pubkey(void *arg) {
    const Sm2Arg *a = (const Sm2Arg *)arg;
    ECPoint p = sm2_get_public_key(&a->d);
    sink += (size_t)p.x.value.limbs[0];
}

static void bench_sign(void *arg) {
    const Sm2Arg *a = (const Sm2Arg *)arg;
    char *s = sm2_sign(USER_ID, MESSAGE, a->pri);
    sink += (size_t)s[0];
    free(s);
}

static void bench_verify(void *arg) {
    const Sm2Arg *a = (const Sm2Arg *)arg;
    if (!sm2_verify(USER_ID, a->sig, MESSAGE, a->pub)) {
        abort();
    }
}

static void bench_encrypt(void *arg) {
    const Sm2Arg *a = (const Sm2Arg *)arg;
    char *c = sm2_encrypt(MESSAGE, a->pub);
    sink += (size_t)c[0];
    free(c);
}

static void bench_decrypt(void *arg) {
    const Sm2Arg *a = (const Sm2Arg *)arg;
    char *p = sm2_decrypt(a->cipher, a->pri);
    if (p == NULL) {
        abort();
    }
    free(p);
}

typedef struct {
    BigInt256 da, db, ra, rb;
    ECPoint pa, pb, ra_pub, rb_pub;
} KxArg;

static void bench_key_exchange(void *arg) {
    const KxArg *a = (const KxArg *)arg;
    uint8_t sb[32], sa[32];
    SM2KeySwapParams b = sm2_get_sb(16, a->pa, a->ra_pub, a->pb, &a->db, a->rb_pub, &a->rb, USER_ID,
                                    "BILL456@YAHOO.COM");
    SM2KeySwapParams r;
    hex_to_bytes(b.sb, sb, 32);
    r = sm2_get_sa(16, a->pb, a->rb_pub, a->pa, &a->da, a->ra_pub, &a->ra, USER_ID,
                   "BILL456@YAHOO.COM", sb, 32);
    hex_to_bytes(r.sa, sa, 32);
    if (!r.success || !sm2_check_sa(b.v, b.za, b.zb, a->ra_pub, a->rb_pub, sa, 32)) {
        abort();
    }
}

static char *make_text(size_t n) {
    char *t = (char *)malloc(n + 1);
    size_t i;
    for (i = 0; i < n; i++) {
        t[i] = (char)('a' + (i % 26));
    }
    t[n] = '\0';
    return t;
}

int main(int argc, char **argv) {
    static const size_t sm3_sizes[] = {64, 1024, 1048576};
    static const char *const sm3_names[] = {"SM3 64B", "SM3 1KB", "SM3 1MB"};
    static const size_t sm4_sizes[] = {16, 1024, 1048576};
    static const char *const sm4_enc_names[] = {"SM4 encrypt 16B", "SM4 encrypt 1KB",
                                                "SM4 encrypt 1MB"};
    static const char *const sm4_dec_names[] = {"SM4 decrypt 16B", "SM4 decrypt 1KB",
                                                "SM4 decrypt 1MB"};
    SM4 sm4;
    Sm2Arg s2;
    KxArg kx;
    int i;

    if (argc > 1) {
        min_seconds = atof(argv[1]) / 1000.0;
    }
    if (argc > 2) {
        repeats = atoi(argv[2]);
    }

    for (i = 0; i < 3; i++) {
        char *t = make_text(sm3_sizes[i]);
        Sm3Arg a;
        a.data = (const uint8_t *)t;
        a.len = sm3_sizes[i];
        report_bytes(sm3_names[i], bench_sm3, &a, a.len);
        free(t);
    }

    sm4_init(&sm4);
    sm4_set_key(&sm4, sm4_key, 16, sm4_iv, 16);
    report_ops("SM4 key schedule", bench_sm4_key, &sm4);
    for (i = 0; i < 3; i++) {
        char *t = make_text(sm4_sizes[i]);
        char *c = sm4_encrypt(&sm4, t);
        Sm4Arg e, d;
        e.ctx = &sm4;
        e.text = t;
        d.ctx = &sm4;
        d.text = c;
        report_bytes(sm4_enc_names[i], bench_sm4_enc, &e, sm4_sizes[i]);
        report_bytes(sm4_dec_names[i], bench_sm4_dec, &d, sm4_sizes[i]);
        free(c);
        free(t);
    }

    sm2_gen_keypair(s2.pri, s2.pub);
    s2.d = bigint256_from_hex(s2.pri);
    s2.sig = sm2_sign(USER_ID, MESSAGE, s2.pri);
    s2.cipher = sm2_encrypt(MESSAGE, s2.pub);
    report_ops("SM2 keygen", bench_keygen, NULL);
    report_ops("SM2 public key (d*G)", bench_pubkey, &s2);
    report_ops("SM2 sign", bench_sign, &s2);
    report_ops("SM2 verify", bench_verify, &s2);
    report_ops("SM2 encrypt", bench_encrypt, &s2);
    report_ops("SM2 decrypt", bench_decrypt, &s2);
    free(s2.sig);
    free(s2.cipher);

    kx.da = bigint256_from_hex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE");
    kx.ra = bigint256_from_hex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563");
    kx.db = bigint256_from_hex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53");
    kx.rb = bigint256_from_hex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80");
    kx.pa = sm2_get_public_key(&kx.da);
    kx.pb = sm2_get_public_key(&kx.db);
    kx.ra_pub = sm2_get_public_key(&kx.ra);
    kx.rb_pub = sm2_get_public_key(&kx.rb);
    report_ops("SM2 key exchange (A+B)", bench_key_exchange, &kx);

    return sink == 0xFFFFFFFFu ? 1 : 0;
}
