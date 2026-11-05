#include "smx_internal.h"
#include <string.h>

static const uint32_t sm3_iv[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
};

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define P0(x) ((x) ^ ROL32((x), 9) ^ ROL32((x), 17))
#define P1(x) ((x) ^ ROL32((x), 15) ^ ROL32((x), 23))

#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | (((x) | (y)) & (z)))
#define GG1(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))

/* W[j] from W[j-16], W[j-9], W[j-3], W[j-13] and W[j-6], written over W[j-16]. */
#define EXPAND(w16, w9, w3, w13, w6) (P1((w16) ^ (w9) ^ ROL32((w3), 15)) ^ ROL32((w13), 7) ^ (w6))

/*
 * One round without moving the state: callers rotate the variable names instead. t is T_j
 * rotated left by j (mod 32), folded into a constant; wj4 is W[j + 4], so wj ^ wj4 is W'[j].
 */
#define ROUND(FF, GG, a, b, c, d, e, f, g, h, t, wj, wj4)                                          \
    do {                                                                                           \
        uint32_t a12 = ROL32(a, 12);                                                               \
        uint32_t ss1 = ROL32(a12 + (e) + (uint32_t)(t), 7);                                        \
        uint32_t tt2 = GG(e, f, g) + (h) + ss1 + (wj);                                             \
        d += FF(a, b, c) + (ss1 ^ a12) + ((wj) ^ (wj4));                                           \
        b = ROL32(b, 9);                                                                           \
        h = P0(tt2);                                                                               \
        f = ROL32(f, 19);                                                                          \
    } while (0)

#define R0(a, b, c, d, e, f, g, h, t, wj, wj4) ROUND(FF0, GG0, a, b, c, d, e, f, g, h, t, wj, wj4)
#define R1(a, b, c, d, e, f, g, h, t, wj, wj4) ROUND(FF1, GG1, a, b, c, d, e, f, g, h, t, wj, wj4)

/*
 * The message schedule lives in 16 variables, each overwritten four rounds before it is next
 * needed, and is expanded between the rounds rather than into an array first. That keeps it in
 * registers, and gives the processor independent work to overlap with each round's chain.
 */
SMX_ALWAYS_INLINE static inline void sm3_compress_body(uint32_t v[8], const uint8_t *p, size_t n) {
    uint32_t v0 = v[0], v1 = v[1], v2 = v[2], v3 = v[3];
    uint32_t v4 = v[4], v5 = v[5], v6 = v[6], v7 = v[7];

    for (; n > 0; n--, p += 64) {
        uint32_t a = v0, b = v1, c = v2, d = v3, e = v4, f = v5, g = v6, h = v7;
        uint32_t w00 = smx_load_be32(p), w01 = smx_load_be32(p + 4);
        uint32_t w02 = smx_load_be32(p + 8), w03 = smx_load_be32(p + 12);
        uint32_t w04 = smx_load_be32(p + 16), w05 = smx_load_be32(p + 20);
        uint32_t w06 = smx_load_be32(p + 24), w07 = smx_load_be32(p + 28);
        uint32_t w08 = smx_load_be32(p + 32), w09 = smx_load_be32(p + 36);
        uint32_t w10 = smx_load_be32(p + 40), w11 = smx_load_be32(p + 44);
        uint32_t w12 = smx_load_be32(p + 48), w13 = smx_load_be32(p + 52);
        uint32_t w14 = smx_load_be32(p + 56), w15 = smx_load_be32(p + 60);

        R0(a, b, c, d, e, f, g, h, 0x79CC4519u, w00, w04);
        R0(d, a, b, c, h, e, f, g, 0xF3988A32u, w01, w05);
        R0(c, d, a, b, g, h, e, f, 0xE7311465u, w02, w06);
        R0(b, c, d, a, f, g, h, e, 0xCE6228CBu, w03, w07);
        R0(a, b, c, d, e, f, g, h, 0x9CC45197u, w04, w08);
        R0(d, a, b, c, h, e, f, g, 0x3988A32Fu, w05, w09);
        R0(c, d, a, b, g, h, e, f, 0x7311465Eu, w06, w10);
        R0(b, c, d, a, f, g, h, e, 0xE6228CBCu, w07, w11);
        R0(a, b, c, d, e, f, g, h, 0xCC451979u, w08, w12);
        R0(d, a, b, c, h, e, f, g, 0x988A32F3u, w09, w13);
        R0(c, d, a, b, g, h, e, f, 0x311465E7u, w10, w14);
        R0(b, c, d, a, f, g, h, e, 0x6228CBCEu, w11, w15);
        w00 = EXPAND(w00, w07, w13, w03, w10);
        R0(a, b, c, d, e, f, g, h, 0xC451979Cu, w12, w00);
        w01 = EXPAND(w01, w08, w14, w04, w11);
        R0(d, a, b, c, h, e, f, g, 0x88A32F39u, w13, w01);
        w02 = EXPAND(w02, w09, w15, w05, w12);
        R0(c, d, a, b, g, h, e, f, 0x11465E73u, w14, w02);
        w03 = EXPAND(w03, w10, w00, w06, w13);
        R0(b, c, d, a, f, g, h, e, 0x228CBCE6u, w15, w03);
        w04 = EXPAND(w04, w11, w01, w07, w14);
        R1(a, b, c, d, e, f, g, h, 0x9D8A7A87u, w00, w04);
        w05 = EXPAND(w05, w12, w02, w08, w15);
        R1(d, a, b, c, h, e, f, g, 0x3B14F50Fu, w01, w05);
        w06 = EXPAND(w06, w13, w03, w09, w00);
        R1(c, d, a, b, g, h, e, f, 0x7629EA1Eu, w02, w06);
        w07 = EXPAND(w07, w14, w04, w10, w01);
        R1(b, c, d, a, f, g, h, e, 0xEC53D43Cu, w03, w07);
        w08 = EXPAND(w08, w15, w05, w11, w02);
        R1(a, b, c, d, e, f, g, h, 0xD8A7A879u, w04, w08);
        w09 = EXPAND(w09, w00, w06, w12, w03);
        R1(d, a, b, c, h, e, f, g, 0xB14F50F3u, w05, w09);
        w10 = EXPAND(w10, w01, w07, w13, w04);
        R1(c, d, a, b, g, h, e, f, 0x629EA1E7u, w06, w10);
        w11 = EXPAND(w11, w02, w08, w14, w05);
        R1(b, c, d, a, f, g, h, e, 0xC53D43CEu, w07, w11);
        w12 = EXPAND(w12, w03, w09, w15, w06);
        R1(a, b, c, d, e, f, g, h, 0x8A7A879Du, w08, w12);
        w13 = EXPAND(w13, w04, w10, w00, w07);
        R1(d, a, b, c, h, e, f, g, 0x14F50F3Bu, w09, w13);
        w14 = EXPAND(w14, w05, w11, w01, w08);
        R1(c, d, a, b, g, h, e, f, 0x29EA1E76u, w10, w14);
        w15 = EXPAND(w15, w06, w12, w02, w09);
        R1(b, c, d, a, f, g, h, e, 0x53D43CECu, w11, w15);
        w00 = EXPAND(w00, w07, w13, w03, w10);
        R1(a, b, c, d, e, f, g, h, 0xA7A879D8u, w12, w00);
        w01 = EXPAND(w01, w08, w14, w04, w11);
        R1(d, a, b, c, h, e, f, g, 0x4F50F3B1u, w13, w01);
        w02 = EXPAND(w02, w09, w15, w05, w12);
        R1(c, d, a, b, g, h, e, f, 0x9EA1E762u, w14, w02);
        w03 = EXPAND(w03, w10, w00, w06, w13);
        R1(b, c, d, a, f, g, h, e, 0x3D43CEC5u, w15, w03);
        w04 = EXPAND(w04, w11, w01, w07, w14);
        R1(a, b, c, d, e, f, g, h, 0x7A879D8Au, w00, w04);
        w05 = EXPAND(w05, w12, w02, w08, w15);
        R1(d, a, b, c, h, e, f, g, 0xF50F3B14u, w01, w05);
        w06 = EXPAND(w06, w13, w03, w09, w00);
        R1(c, d, a, b, g, h, e, f, 0xEA1E7629u, w02, w06);
        w07 = EXPAND(w07, w14, w04, w10, w01);
        R1(b, c, d, a, f, g, h, e, 0xD43CEC53u, w03, w07);
        w08 = EXPAND(w08, w15, w05, w11, w02);
        R1(a, b, c, d, e, f, g, h, 0xA879D8A7u, w04, w08);
        w09 = EXPAND(w09, w00, w06, w12, w03);
        R1(d, a, b, c, h, e, f, g, 0x50F3B14Fu, w05, w09);
        w10 = EXPAND(w10, w01, w07, w13, w04);
        R1(c, d, a, b, g, h, e, f, 0xA1E7629Eu, w06, w10);
        w11 = EXPAND(w11, w02, w08, w14, w05);
        R1(b, c, d, a, f, g, h, e, 0x43CEC53Du, w07, w11);
        w12 = EXPAND(w12, w03, w09, w15, w06);
        R1(a, b, c, d, e, f, g, h, 0x879D8A7Au, w08, w12);
        w13 = EXPAND(w13, w04, w10, w00, w07);
        R1(d, a, b, c, h, e, f, g, 0x0F3B14F5u, w09, w13);
        w14 = EXPAND(w14, w05, w11, w01, w08);
        R1(c, d, a, b, g, h, e, f, 0x1E7629EAu, w10, w14);
        w15 = EXPAND(w15, w06, w12, w02, w09);
        R1(b, c, d, a, f, g, h, e, 0x3CEC53D4u, w11, w15);
        w00 = EXPAND(w00, w07, w13, w03, w10);
        R1(a, b, c, d, e, f, g, h, 0x79D8A7A8u, w12, w00);
        w01 = EXPAND(w01, w08, w14, w04, w11);
        R1(d, a, b, c, h, e, f, g, 0xF3B14F50u, w13, w01);
        w02 = EXPAND(w02, w09, w15, w05, w12);
        R1(c, d, a, b, g, h, e, f, 0xE7629EA1u, w14, w02);
        w03 = EXPAND(w03, w10, w00, w06, w13);
        R1(b, c, d, a, f, g, h, e, 0xCEC53D43u, w15, w03);
        w04 = EXPAND(w04, w11, w01, w07, w14);
        R1(a, b, c, d, e, f, g, h, 0x9D8A7A87u, w00, w04);
        w05 = EXPAND(w05, w12, w02, w08, w15);
        R1(d, a, b, c, h, e, f, g, 0x3B14F50Fu, w01, w05);
        w06 = EXPAND(w06, w13, w03, w09, w00);
        R1(c, d, a, b, g, h, e, f, 0x7629EA1Eu, w02, w06);
        w07 = EXPAND(w07, w14, w04, w10, w01);
        R1(b, c, d, a, f, g, h, e, 0xEC53D43Cu, w03, w07);
        w08 = EXPAND(w08, w15, w05, w11, w02);
        R1(a, b, c, d, e, f, g, h, 0xD8A7A879u, w04, w08);
        w09 = EXPAND(w09, w00, w06, w12, w03);
        R1(d, a, b, c, h, e, f, g, 0xB14F50F3u, w05, w09);
        w10 = EXPAND(w10, w01, w07, w13, w04);
        R1(c, d, a, b, g, h, e, f, 0x629EA1E7u, w06, w10);
        w11 = EXPAND(w11, w02, w08, w14, w05);
        R1(b, c, d, a, f, g, h, e, 0xC53D43CEu, w07, w11);
        w12 = EXPAND(w12, w03, w09, w15, w06);
        R1(a, b, c, d, e, f, g, h, 0x8A7A879Du, w08, w12);
        w13 = EXPAND(w13, w04, w10, w00, w07);
        R1(d, a, b, c, h, e, f, g, 0x14F50F3Bu, w09, w13);
        w14 = EXPAND(w14, w05, w11, w01, w08);
        R1(c, d, a, b, g, h, e, f, 0x29EA1E76u, w10, w14);
        w15 = EXPAND(w15, w06, w12, w02, w09);
        R1(b, c, d, a, f, g, h, e, 0x53D43CECu, w11, w15);
        w00 = EXPAND(w00, w07, w13, w03, w10);
        R1(a, b, c, d, e, f, g, h, 0xA7A879D8u, w12, w00);
        w01 = EXPAND(w01, w08, w14, w04, w11);
        R1(d, a, b, c, h, e, f, g, 0x4F50F3B1u, w13, w01);
        w02 = EXPAND(w02, w09, w15, w05, w12);
        R1(c, d, a, b, g, h, e, f, 0x9EA1E762u, w14, w02);
        w03 = EXPAND(w03, w10, w00, w06, w13);
        R1(b, c, d, a, f, g, h, e, 0x3D43CEC5u, w15, w03);

        v0 ^= a;
        v1 ^= b;
        v2 ^= c;
        v3 ^= d;
        v4 ^= e;
        v5 ^= f;
        v6 ^= g;
        v7 ^= h;
    }

    v[0] = v0;
    v[1] = v1;
    v[2] = v2;
    v[3] = v3;
    v[4] = v4;
    v[5] = v5;
    v[6] = v6;
    v[7] = v7;
}

/*
 * x86-64 with BMI2 gets a second copy of the same code, built so the rotates become rorx: it
 * has three operands, which saves a move per rotate. About 13% faster with gcc. The CPU is
 * asked once, before main(); define SMX_NO_SIMD or SMX_SM3_NO_BMI2 to build only the portable
 * copy, which `make check-fallbacks` tests.
 */
#if defined(__x86_64__) && !defined(SMX_NO_SIMD) && !defined(SMX_SM3_NO_BMI2) &&                   \
    (defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 5))
#include <cpuid.h>

static void sm3_compress_portable(uint32_t v[8], const uint8_t *p, size_t n) {
    sm3_compress_body(v, p, n);
}

__attribute__((target("bmi2"))) static void sm3_compress_bmi2(uint32_t v[8], const uint8_t *p,
                                                              size_t n) {
    sm3_compress_body(v, p, n);
}

/* Written only before main() runs, so it needs no synchronization. */
static void (*sm3_compress_impl)(uint32_t v[8], const uint8_t *p, size_t n) = sm3_compress_portable;

__attribute__((constructor)) static void sm3_detect_cpu(void) {
    unsigned eax, ebx, ecx, edx;
    if (__get_cpuid_max(0, NULL) >= 7) {
        __cpuid_count(7, 0, eax, ebx, ecx, edx);
        if ((ebx >> 8) & 1) {
            sm3_compress_impl = sm3_compress_bmi2;
        }
    }
}

void smx_sm3_compress(uint32_t v[8], const uint8_t *p, size_t n) {
    sm3_compress_impl(v, p, n);
}
#else
void smx_sm3_compress(uint32_t v[8], const uint8_t *p, size_t n) {
    sm3_compress_body(v, p, n);
}
#endif

/* SM3 hashes at most 2^64 - 1 bits; whole bytes give a limit of 2^61 - 1 bytes. */
#define SM3_MAX_BYTES (((uint64_t)1 << 61) - 1)

/* buff_len value marking a context that received too much input, or was never set up. */
#define SM3_FAILED (-1)
/* buff_len value after a failed sm3_finish: the failure stands until new data or sm3_init. */
#define SM3_FINISHED_FAILED (-2)

void sm3_init(SM3 *ctx) {
    if (ctx == NULL) {
        return;
    }
    memcpy(ctx->v, sm3_iv, sizeof(sm3_iv));
    ctx->buff_len = 0;
    ctx->data_bits_len = 0;
    memset(ctx->hash_bytes, 0, sizeof(ctx->hash_bytes));
    memset(ctx->hash_hex, 0, sizeof(ctx->hash_hex));
}

/* A digest in the context describes earlier input, so any further use takes it away. */
static void sm3_forget_digest(SM3 *ctx) {
    if (ctx->hash_hex[0] != '\0') {
        memset(ctx->hash_bytes, 0, sizeof(ctx->hash_bytes));
        memset(ctx->hash_hex, 0, sizeof(ctx->hash_hex));
    }
}

/* Accounts for len more bytes; marks the context failed if it cannot represent them. */
static int sm3_reserve(SM3 *ctx, size_t len) {
    uint64_t used;
    sm3_forget_digest(ctx);
    if (ctx->buff_len == SM3_FINISHED_FAILED) {
        ctx->buff_len = 0;
    }
    if (ctx->buff_len < 0 || ctx->buff_len >= 64) {
        ctx->buff_len = SM3_FAILED;
        return 0;
    }
    used = ctx->data_bits_len / 8;
    if (used > SM3_MAX_BYTES || (uint64_t)len > SM3_MAX_BYTES - used) {
        ctx->buff_len = SM3_FAILED;
        return 0;
    }
    ctx->data_bits_len += (uint64_t)len * 8;
    return 1;
}

void sm3_update_byte(SM3 *ctx, uint8_t b) {
    if (ctx == NULL || !sm3_reserve(ctx, 1)) {
        return;
    }
    ctx->buff[ctx->buff_len++] = b;
    if (ctx->buff_len == 64) {
        smx_sm3_compress(ctx->v, ctx->buff, 1);
        ctx->buff_len = 0;
    }
}

void sm3_update(SM3 *ctx, const uint8_t *data, size_t len) {
    size_t blocks;

    if (ctx == NULL) {
        return;
    }
    if (len == 0) {
        sm3_forget_digest(ctx);
        if (ctx->buff_len == SM3_FINISHED_FAILED) {
            ctx->buff_len = 0;
        }
        return;
    }
    if (data == NULL) {
        ctx->buff_len = SM3_FAILED; /* the digest must not pretend this input was hashed */
        return;
    }
    if (!sm3_reserve(ctx, len)) {
        return;
    }

    if (ctx->buff_len != 0) {
        size_t room = 64 - (size_t)ctx->buff_len;
        size_t take = len < room ? len : room;
        memmove(ctx->buff + ctx->buff_len, data, take);
        ctx->buff_len += (int)take;
        data += take;
        len -= take;
        if (ctx->buff_len < 64) {
            return;
        }
        smx_sm3_compress(ctx->v, ctx->buff, 1);
        ctx->buff_len = 0;
    }

    /* whole blocks are hashed straight from the caller's buffer */
    blocks = len / 64;
    if (blocks > 0) {
        smx_sm3_compress(ctx->v, data, blocks);
        data += blocks * 64;
        len -= blocks * 64;
    }
    if (len > 0) {
        memmove(ctx->buff, data, len);
        ctx->buff_len = (int)len;
    }
}

/* Returns 0, with the context reset and out zeroed, if the context had failed. */
static int sm3_finalize(SM3 *ctx, uint8_t out[32]) {
    uint64_t total_bits = ctx->data_bits_len;
    int ok = ctx->buff_len >= 0 && ctx->buff_len < 64;
    int i;

    if (ok) {
        size_t pos = (size_t)ctx->buff_len;
        ctx->buff[pos++] = 0x80;
        if (pos > 56) {
            memset(ctx->buff + pos, 0, 64 - pos);
            smx_sm3_compress(ctx->v, ctx->buff, 1);
            pos = 0;
        }
        memset(ctx->buff + pos, 0, 56 - pos);
        smx_store_be64(ctx->buff + 56, total_bits);
        smx_sm3_compress(ctx->v, ctx->buff, 1);
        for (i = 0; i < 8; i++) {
            smx_store_be32(out + i * 4, ctx->v[i]);
        }
    } else {
        memset(out, 0, 32);
    }

    /* reset for reuse; the chaining state may derive from secrets */
    memcpy(ctx->v, sm3_iv, sizeof(sm3_iv));
    ctx->buff_len = 0;
    ctx->data_bits_len = 0;
    smx_wipe(ctx->buff, sizeof(ctx->buff));
    return ok;
}

void smx_sm3_finish_bytes(SM3 *ctx, uint8_t out[32]) {
    (void)sm3_finalize(ctx, out);
}

void sm3_finish(SM3 *ctx) {
    if (ctx == NULL) {
        return;
    }
    /* a second finish with nothing in between keeps the result: the digest, or the failure */
    if (ctx->buff_len == SM3_FINISHED_FAILED ||
        (ctx->hash_hex[0] != '\0' && ctx->buff_len == 0 && ctx->data_bits_len == 0)) {
        return;
    }
    if (sm3_finalize(ctx, ctx->hash_bytes)) {
        smx_hex_encode(ctx->hash_bytes, 32, ctx->hash_hex, 'A');
        ctx->hash_hex[64] = '\0';
    } else {
        memset(ctx->hash_hex, 0, sizeof(ctx->hash_hex));
        ctx->buff_len = SM3_FINISHED_FAILED;
    }
}
