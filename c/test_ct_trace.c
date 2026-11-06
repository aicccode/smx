/*
 * Compares machine-level control flow between secret inputs. A child runs each secret-handling
 * operation on several inputs while this process single-steps it with ptrace and hashes the
 * instruction pointer. Identical hashes mean no branch depended on the data.
 *
 * It catches what reading the source cannot, and what a static check of branch shapes can
 * miss: at commit 751d51f clang -O3 made the masked table scan in ec_mul_g skip entries, by a
 * backward branch that looked like a loop counter. It covers control flow only. Memory
 * addresses are the job of test_ct.c (MemorySanitizer) and tools/check_ct_asm.py. SM4 on this
 * branch indexes tables with secret data, so only its control flow is held constant here.
 *
 * Built by tools/check_ct_trace.sh, for Linux on x86-64 only: elsewhere it reports that it
 * did not run. malloc is replaced by a bump allocator so the heap adds no variation of its own.
 *
 * Usage: test_ct_trace [label]. Exit status 1 if any trace differs. To debug an operation, set
 * DOP to its index and DA, DB to two inputs, to print where they first part.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) && defined(__x86_64__)

static unsigned char bump_mem[1 << 24];
static size_t bump_off;

__attribute__((noinline)) static void *bump(size_t n) {
    void *p = bump_mem + bump_off;
    bump_off = (bump_off + n + 63) & ~(size_t)63;
    return p;
}

__attribute__((noinline)) static void no_free(void *p) {
    (void)p;
    __asm__ volatile("");
}

#define malloc(x) bump(x)
#define free(x) no_free(x)
#include "sm2.c"
#include "sm4.c"
#undef malloc
#undef free

#include <signal.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define OPAQUE(p) __asm__ volatile("" : "+r"(p) : : "memory")
#define NI __attribute__((noinline, used)) static

__attribute__((noinline)) void mark_start(int op, int input) {
    __asm__ volatile("" : : "r"(op), "r"(input));
}

__attribute__((noinline)) void mark_end(void) {
    __asm__ volatile("");
}

/* Scalars with long runs, each sign of digit, and values next to n, including n - 6. */
static uint64_t K[][4] = {
    {1, 0, 0, 0},
    {2, 0, 0, 0},
    {0x53BBF40939D54122ULL, 0x7203DF6B21C6052BULL, ~0ULL, 0xFFFFFFFEFFFFFFFFULL},
    {0x53BBF40939D5411DULL, 0x7203DF6B21C6052BULL, ~0ULL, 0xFFFFFFFEFFFFFFFFULL},
    {0, 0, 0, 0x4000000000000000ULL},
    {0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL, 0x1111111111111111ULL, 0x2222222222222222ULL},
    {0x8421084210842108ULL, 0x4210842108421084ULL, 0x2108421084210842ULL, 0x1084210842108421ULL},
    {~0ULL, ~0ULL, 0, 0},
    {0, 0, ~0ULL, 0x7FFFFFFFFFFFFFFFULL},
};
#define K_COUNT ((int)(sizeof(K) / sizeof(K[0])))
#define MUL_CT_INPUTS 4 /* each is about a million instructions */

static const char *const PRI[] = {
    "0000000000000000000000000000000000000000000000000000000000000001",
    "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
    "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
};
#define PRI_COUNT ((int)(sizeof(PRI) / sizeof(PRI[0])))

static const char CIPHERTEXT[] =
    "0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73"
    "e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0"
    "59983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd8766"
    "21886ca989ca9c7d58087307ca93092d651efa";

enum {
    OP_MUL_G,
    OP_MUL_CT,
    OP_FE_INV,
    OP_FN_INV,
    OP_FN_MUL,
    OP_FE_MUL,
    OP_MOD_ADD,
    OP_MOD_SUB,
    OP_COMPARE,
    OP_HEX_ENC,
    OP_HEX_ENC32,
    OP_HEX_DEC,
    OP_HEX_DEC_LOWER,
    OP_TO_HEX,
    OP_PKCS7,
    OP_SET_KEY,
    OP_SM4_BLOCKS,
    OP_SM4_ENCRYPT,
    OP_SM4_DECRYPT,
    OP_SM4_DECRYPT_CORE,
    OP_PARSE_KEY,
    OP_BYTES_EQUAL,
    OP_SIGN,
    OP_DECRYPT,
    OP_KEY_EXCHANGE,
    OP_COUNT
};

static const char *const OP_NAMES[] = {
    "ec_mul_g",         "ec_mul_ct",        "fe_inv",
    "fn_inv",           "fn_mul",           "fe_mul",
    "mod_add",          "mod_sub",          "compare",
    "hex_encode 37",    "hex_encode 32",    "hex_decode",
    "hex_decode_lower", "bigint256_to_hex", "pkcs7_check",
    "sm4_set_key",      "sm4_blocks",       "sm4_encrypt_bytes",
    "sm4_decrypt",      "sm4_decrypt_core", "parse_private_key",
    "bytes_equal",      "sm2_sign",         "sm2_decrypt",
    "sm2_get_sa",
};

NI void op_mul_g(Jac *r, const uint64_t *k) {
    ec_mul_g(r, k);
}
NI void op_mul_ct(Jac *r, const Jac *b, const uint64_t *k) {
    ec_mul_ct(r, b, k);
}
NI void op_fe_inv(uint64_t *r, const uint64_t *a) {
    fe_inv(r, a);
}
NI void op_fn_inv(uint64_t *r, const uint64_t *a) {
    fn_inv(r, a);
}
NI void op_fn_mul(uint64_t *r, const uint64_t *a, const uint64_t *b) {
    fn_mul(r, a, b);
}
NI void op_fe_mul(uint64_t *r, const uint64_t *a, const uint64_t *b) {
    fe_mul(r, a, b);
}
NI void op_hex_enc(const uint8_t *b, char *h, size_t n) {
    smx_hex_encode(b, n, h, 'a');
}
NI int op_hex_dec(const char *h, uint8_t *b) {
    return smx_hex_decode(h, 37, b);
}
NI int op_hex_dec_lower(const char *h, uint8_t *b) {
    return smx_hex_decode_lower(h, 37, b);
}
NI uint64_t op_pkcs7(const uint8_t *b, size_t *o) {
    return pkcs7_check(b, 32, o);
}
NI int op_equal(const uint8_t *a, const uint8_t *b) {
    return bytes_equal(a, b, 32);
}
NI int op_parse(const char *h, BigInt256 *d) {
    return parse_private_key(h, d);
}
NI void op_blocks(const uint32_t *rk, const uint8_t *i, uint8_t *o) {
    sm4_blocks(rk, i, o);
}
NI uint64_t op_decrypt_core(const SM4 *c, uint8_t *b, size_t n, size_t *o) {
    return sm4_decrypt_core(c, b, n, o);
}

#ifdef __clang__
__attribute__((optnone, noinline))
#else
__attribute__((optimize("O0"), noinline))
#endif
static void child(void) {
    int i;
    Jac base;
    static volatile uint64_t sink;
    static uint64_t (*kp)[4] = K;
    static char keys[PRI_COUNT][65];
    static char bad_ct[sizeof(CIPHERTEXT)];

    OPAQUE(kp);
    jac_set_affine(&base, EC_GX, EC_GY);
    jac_double(&base, &base);
    for (i = 0; i < PRI_COUNT; i++) {
        strcpy(keys[i], PRI[i]);
    }
    strcpy(bad_ct, CIPHERTEXT);
    bad_ct[sizeof(CIPHERTEXT) - 2] = bad_ct[sizeof(CIPHERTEXT) - 2] == '0' ? '1' : '0';

    for (i = 0; i < K_COUNT; i++) {
        Jac r;
        mark_start(OP_MUL_G, i);
        op_mul_g(&r, kp[i]);
        mark_end();
        sink += r.x[0];
    }
    for (i = 0; i < MUL_CT_INPUTS; i++) {
        Jac r;
        /* inputs 2 and 3 are near n, so the complete addition at the end is exercised */
        mark_start(OP_MUL_CT, i);
        op_mul_ct(&r, &base, kp[i + 2]);
        mark_end();
        sink += r.x[0];
    }
    for (i = 0; i < K_COUNT; i++) {
        uint64_t r[4];
        const uint64_t *a0 = kp[i], *a1 = kp[(i + 1) % K_COUNT];
        BigInt256 a, b, o;
        char h[129], fixed[65];
        uint8_t by[64], bk[64], key[16], iv[16], in[128], out[128], x1[32], x2[32];
        uint32_t rkrev[32];
        SM4 s;
        size_t len;
        char *e;
        uint8_t *d;
        int q, p, c;

        mark_start(OP_FE_INV, i);
        op_fe_inv(r, a0);
        mark_end();
        sink += r[0];
        mark_start(OP_FN_INV, i);
        op_fn_inv(r, a0);
        mark_end();
        sink += r[0];
        mark_start(OP_FN_MUL, i);
        op_fn_mul(r, a0, a1);
        mark_end();
        sink += r[0];
        mark_start(OP_FE_MUL, i);
        op_fe_mul(r, a0, a1);
        mark_end();
        sink += r[0];

        memcpy(a.limbs, a0, 32);
        memcpy(b.limbs, a1, 32);
        mark_start(OP_MOD_ADD, i);
        bigint256_mod_add(&o, &a, &b, &SM2_N);
        mark_end();
        sink += o.limbs[0];
        mark_start(OP_MOD_SUB, i);
        bigint256_mod_sub(&o, &a, &b, &SM2_N);
        mark_end();
        sink += o.limbs[0];
        mark_start(OP_COMPARE, i);
        c = bigint256_compare(&a, &b);
        mark_end();
        sink += (uint64_t)c;

        memcpy(by, a0, 32);
        memcpy(by + 32, a1, 32);
        mark_start(OP_HEX_ENC, i);
        op_hex_enc(by, h, 37);
        mark_end();
        mark_start(OP_HEX_ENC32, i);
        op_hex_enc(by, fixed, 32);
        mark_end();
        mark_start(OP_TO_HEX, i);
        bigint256_to_hex_lower(&a, fixed);
        mark_end();
        h[74] = 0;
        mark_start(OP_HEX_DEC, i);
        c = op_hex_dec(h, bk);
        mark_end();
        sink += (uint64_t)c + bk[0];
        mark_start(OP_HEX_DEC_LOWER, i);
        c = op_hex_dec_lower(h, bk);
        mark_end();
        sink += (uint64_t)c + bk[0];

        memcpy(key, a0, 16);
        memset(iv, 0, 16);
        sm4_init(&s);
        mark_start(OP_SET_KEY, i);
        sm4_set_key(&s, key, 16, iv, 16);
        mark_end();
        for (q = 0; q < 128; q++) {
            in[q] = by[q % 64];
        }
        for (q = 0; q < 32; q++) {
            rkrev[q] = s.rk[31 - q];
        }
        mark_start(OP_SM4_BLOCKS, i);
        op_blocks(rkrev, in, out);
        mark_end();
        sink += out[0];
        mark_start(OP_SM4_ENCRYPT, i);
        e = sm4_encrypt_bytes(&s, in, 40);
        mark_end();
        mark_start(OP_SM4_DECRYPT, i);
        d = sm4_decrypt_bytes(&s, e, &len);
        mark_end();
        sink += len;
        (void)d;

        /* every padding byte value, valid or not, through the check alone */
        for (p = 0; p <= 255; p += (p < 20 ? 1 : 47)) {
            uint8_t blk[32];
            size_t ol;
            uint64_t v;
            memset(blk, p, 32);
            mark_start(OP_PKCS7, p);
            v = op_pkcs7(blk, &ol);
            mark_end();
            sink += v;
        }

        /*
         * All that follows the hex decode, on ciphertext whose padding comes out valid (the
         * even runs) or invalid (the odd runs). The work must not tell them apart. The
         * ciphertext is the encryption of the data above, with its last block damaged.
         */
        for (p = 0; p < 2; p++) {
            static uint8_t buf[64];
            size_t plain_len;
            uint64_t v;
            hex_to_bytes(e, buf, sizeof(buf));
            if (p == 1) {
                buf[31] ^= 0x55; /* the previous block feeds the padding byte directly */
            }
            mark_start(OP_SM4_DECRYPT_CORE, i * 2 + p);
            v = op_decrypt_core(&s, buf, 48, &plain_len);
            mark_end();
            sink += v;
        }

        memcpy(x1, by, 32);
        memcpy(x2, by, 32);
        x2[i % 32] ^= 1;
        mark_start(OP_BYTES_EQUAL, i);
        c = op_equal(x1, x2);
        mark_end();
        sink += (uint64_t)c;
        bump_off = 0;
    }
    for (i = 0; i < PRI_COUNT; i++) {
        BigInt256 d;
        int ok;
        mark_start(OP_PARSE_KEY, i);
        ok = op_parse(keys[i], &d);
        mark_end();
        sink += (uint64_t)ok;
    }
    for (i = 0; i < PRI_COUNT; i++) {
        char *sg;
        mark_start(OP_SIGN, i);
        sg = sm2_sign("1234567812345678", "message digest", keys[i]);
        mark_end();
        sink += (uint64_t)(size_t)sg;
        bump_off = 0;
    }
    for (i = 1; i < PRI_COUNT; i++) {
        char *o;
        mark_start(OP_DECRYPT, i);
        o = sm2_decrypt(bad_ct, keys[i]);
        mark_end();
        sink += (uint64_t)(size_t)o;
        bump_off = 0;
    }
    {
        BigInt256 ds[3];
        ECPoint q;
        static uint8_t sb[32];
        memcpy(ds[0].limbs, kp[0], 32);
        memcpy(ds[1].limbs, kp[5], 32);
        memcpy(ds[2].limbs, kp[3], 32);
        q = sm2_get_public_key(&ds[1]);
        for (i = 0; i < 2; i++) {
            SM2KeySwapParams kx;
            mark_start(OP_KEY_EXCHANGE, i);
            kx = sm2_get_sa(16, q, q, q, &ds[i], q, &ds[i + 1], "a", "b", sb, 32);
            mark_end();
            sink += (uint64_t)kx.success;
        }
    }
    _exit(0);
}

#define MAX_INPUTS 300
#define TRACE_LIMIT 5000000

int main(int argc, char **argv) {
    static uint64_t cnt[OP_COUNT][MAX_INPUTS], hash[OP_COUNT][MAX_INPUTS];
    static char seen[OP_COUNT][MAX_INPUTS];
    const char *dop = getenv("DOP");
    int want = dop ? atoi(dop) : -1;
    int wa = getenv("DA") ? atoi(getenv("DA")) : 0, wb = getenv("DB") ? atoi(getenv("DB")) : 1;
    uint64_t *ta = NULL, *tb = NULL;
    size_t na = 0, nb = 0;
    int cur = -1, ci = 0, status, op, any_bad = 0;
    uint64_t c = 0, h = 0, total = 0;
    struct user_regs_struct regs;
    pid_t pid = fork();

    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
            _exit(77);
        }
        raise(SIGSTOP);
        child();
    }
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        printf("ptrace is not permitted here; the trace check did not run\n");
        return WEXITSTATUS(status) == 77 ? 77 : 2;
    }
    if (want >= 0) {
        ta = (uint64_t *)calloc(TRACE_LIMIT, 8);
        tb = (uint64_t *)calloc(TRACE_LIMIT, 8);
    }
    for (;;) {
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            break;
        }
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        total++;
        if (regs.rip == (uint64_t)(size_t)mark_start) {
            cur = (int)regs.rdi;
            ci = (int)regs.rsi;
            c = 0;
            h = 14695981039346656037ULL;
            continue;
        }
        if (regs.rip == (uint64_t)(size_t)mark_end) {
            if (cur >= 0) {
                cnt[cur][ci] = c;
                hash[cur][ci] = h;
                seen[cur][ci] = 1;
                cur = -1;
                if (want >= 0 && na != 0 && nb != 0) {
                    kill(pid, SIGKILL);
                    break;
                }
            }
            continue;
        }
        if (cur >= 0) {
            c++;
            h = (h ^ regs.rip) * 1099511628211ULL;
            if (cur == want && ci == wa && na < TRACE_LIMIT) {
                ta[na++] = regs.rip;
            }
            if (cur == want && ci == wb && nb < TRACE_LIMIT) {
                tb[nb++] = regs.rip;
            }
        }
    }
    if (want >= 0) {
        size_t i = 0;
        while (i < na && i < nb && ta[i] == tb[i]) {
            i++;
        }
        printf("lengths %zu %zu, first difference at %zu\n", na, nb, i);
        if (i < na && i < nb) {
            size_t from = i > 6 ? i - 6 : 0, j;
            for (j = from; j < i + 6 && j < na; j++) {
                printf("A %#lx\n", (unsigned long)ta[j]);
            }
            for (j = from; j < i + 6 && j < nb; j++) {
                printf("B %#lx\n", (unsigned long)tb[j]);
            }
        }
        return 0;
    }
    for (op = 0; op < OP_COUNT; op++) {
        int ref = -1, n = 0, diff = 0, i;
        uint64_t low = ~(uint64_t)0, high = 0;
        for (i = 0; i < MAX_INPUTS; i++) {
            if (seen[op][i]) {
                if (ref < 0) {
                    ref = i;
                }
                n++;
                diff += hash[op][i] != hash[op][ref];
                low = cnt[op][i] < low ? cnt[op][i] : low;
                high = cnt[op][i] > high ? cnt[op][i] : high;
            }
        }
        if (n < 2) {
            printf("%-20s only %d inputs: the check did not exercise it\n", OP_NAMES[op], n);
            any_bad = 1;
        } else if (diff != 0) {
            printf("%-20s inputs=%d instructions=%llu..%llu TRACE DIFFERS\n", OP_NAMES[op], n,
                   (unsigned long long)low, (unsigned long long)high);
            any_bad = 1;
        }
    }
    printf("%s: %s, %llu steps\n", argc > 1 ? argv[1] : "trace",
           any_bad ? "DIFFERS" : "all traces identical", (unsigned long long)total);
    return any_bad;
}

#else

int main(void) {
    printf("the trace check needs Linux on x86-64; it did not run\n");
    return 77;
}

#endif
