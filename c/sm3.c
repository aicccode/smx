#include "smx_internal.h"
#include <string.h>

#ifdef SMX_HAVE_SSE2
#include <emmintrin.h>
#endif

static const uint32_t sm3_iv[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
};

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define P0(x) ((x) ^ ROL32((x), 9) ^ ROL32((x), 17))
#define P1(x) ((x) ^ ROL32((x), 15) ^ ROL32((x), 23))

#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define GG1(x, y, z) ((((y) ^ (z)) & (x)) ^ (z))

/*
 * One round without moving the state: callers rotate the variable names instead.
 * t is T_j rotated left by j (mod 32), already folded into a constant.
 */
#define ROUND(FF, GG, a, b, c, d, e, f, g, h, t, j)                                                \
    do {                                                                                           \
        uint32_t a12 = ROL32(a, 12);                                                               \
        uint32_t s = a12 + (e) + (uint32_t)(t);                                                    \
        uint32_t ss1 = ROL32(s, 7);                                                                \
        uint32_t tt2 = GG(e, f, g) + (h) + ss1 + w[j];                                             \
        d += FF(a, b, c) + (ss1 ^ a12) + (w[j] ^ w[(j) + 4]);                                      \
        b = ROL32(b, 9);                                                                           \
        h = P0(tt2);                                                                               \
        f = ROL32(f, 19);                                                                          \
    } while (0)

#define R0(a, b, c, d, e, f, g, h, t, j) ROUND(FF0, GG0, a, b, c, d, e, f, g, h, t, j)
#define R1(a, b, c, d, e, f, g, h, t, j) ROUND(FF1, GG1, a, b, c, d, e, f, g, h, t, j)

/*
 * Message expansion: w[0..67] from one block. Each W[j] depends on W[j-3], so three
 * words can be computed at once; SSE2 is always there on x86-64 and this step takes
 * a large part of a compression. The fourth lane of each store is overwritten by
 * the next one, which is why w needs room past index 67.
 */
#define SM3_W_WORDS 71

static inline void sm3_expand(uint32_t w[SM3_W_WORDS], const uint8_t *p) {
    int j;
    for (j = 0; j < 16; j++) {
        w[j] = smx_load_be32(p + j * 4);
    }
#ifdef SMX_HAVE_SSE2
#define SM3_XMM_LOAD(i) _mm_loadu_si128((const __m128i *)(const void *)&w[i])
#define SM3_XMM_ROL(x, n) _mm_or_si128(_mm_slli_epi32(x, n), _mm_srli_epi32(x, 32 - (n)))
    w[16] = 0; /* read by the first load as the unused fourth lane */
    for (j = 16; j < 68; j += 3) {
        __m128i x = _mm_xor_si128(_mm_xor_si128(SM3_XMM_LOAD(j - 16), SM3_XMM_LOAD(j - 9)),
                                  SM3_XMM_ROL(SM3_XMM_LOAD(j - 3), 15));
        __m128i y = _mm_xor_si128(_mm_xor_si128(x, SM3_XMM_ROL(x, 15)), SM3_XMM_ROL(x, 23));
        __m128i z = _mm_xor_si128(_mm_xor_si128(y, SM3_XMM_ROL(SM3_XMM_LOAD(j - 13), 7)),
                                  SM3_XMM_LOAD(j - 6));
        _mm_storeu_si128((__m128i *)(void *)&w[j], z);
    }
#undef SM3_XMM_LOAD
#undef SM3_XMM_ROL
#else
    for (j = 16; j < 68; j++) {
        uint32_t x = w[j - 16] ^ w[j - 9] ^ ROL32(w[j - 3], 15);
        w[j] = P1(x) ^ ROL32(w[j - 13], 7) ^ w[j - 6];
    }
#endif
}

void smx_sm3_compress(uint32_t v[8], const uint8_t *p, size_t n) {
    uint32_t v0 = v[0], v1 = v[1], v2 = v[2], v3 = v[3];
    uint32_t v4 = v[4], v5 = v[5], v6 = v[6], v7 = v[7];

    for (; n > 0; n--, p += 64) {
        uint32_t w[SM3_W_WORDS];
        uint32_t a = v0, b = v1, c = v2, d = v3, e = v4, f = v5, g = v6, h = v7;

        sm3_expand(w, p);

        R0(a, b, c, d, e, f, g, h, 0x79CC4519u, 0);
        R0(d, a, b, c, h, e, f, g, 0xF3988A32u, 1);
        R0(c, d, a, b, g, h, e, f, 0xE7311465u, 2);
        R0(b, c, d, a, f, g, h, e, 0xCE6228CBu, 3);
        R0(a, b, c, d, e, f, g, h, 0x9CC45197u, 4);
        R0(d, a, b, c, h, e, f, g, 0x3988A32Fu, 5);
        R0(c, d, a, b, g, h, e, f, 0x7311465Eu, 6);
        R0(b, c, d, a, f, g, h, e, 0xE6228CBCu, 7);
        R0(a, b, c, d, e, f, g, h, 0xCC451979u, 8);
        R0(d, a, b, c, h, e, f, g, 0x988A32F3u, 9);
        R0(c, d, a, b, g, h, e, f, 0x311465E7u, 10);
        R0(b, c, d, a, f, g, h, e, 0x6228CBCEu, 11);
        R0(a, b, c, d, e, f, g, h, 0xC451979Cu, 12);
        R0(d, a, b, c, h, e, f, g, 0x88A32F39u, 13);
        R0(c, d, a, b, g, h, e, f, 0x11465E73u, 14);
        R0(b, c, d, a, f, g, h, e, 0x228CBCE6u, 15);
        R1(a, b, c, d, e, f, g, h, 0x9D8A7A87u, 16);
        R1(d, a, b, c, h, e, f, g, 0x3B14F50Fu, 17);
        R1(c, d, a, b, g, h, e, f, 0x7629EA1Eu, 18);
        R1(b, c, d, a, f, g, h, e, 0xEC53D43Cu, 19);
        R1(a, b, c, d, e, f, g, h, 0xD8A7A879u, 20);
        R1(d, a, b, c, h, e, f, g, 0xB14F50F3u, 21);
        R1(c, d, a, b, g, h, e, f, 0x629EA1E7u, 22);
        R1(b, c, d, a, f, g, h, e, 0xC53D43CEu, 23);
        R1(a, b, c, d, e, f, g, h, 0x8A7A879Du, 24);
        R1(d, a, b, c, h, e, f, g, 0x14F50F3Bu, 25);
        R1(c, d, a, b, g, h, e, f, 0x29EA1E76u, 26);
        R1(b, c, d, a, f, g, h, e, 0x53D43CECu, 27);
        R1(a, b, c, d, e, f, g, h, 0xA7A879D8u, 28);
        R1(d, a, b, c, h, e, f, g, 0x4F50F3B1u, 29);
        R1(c, d, a, b, g, h, e, f, 0x9EA1E762u, 30);
        R1(b, c, d, a, f, g, h, e, 0x3D43CEC5u, 31);
        R1(a, b, c, d, e, f, g, h, 0x7A879D8Au, 32);
        R1(d, a, b, c, h, e, f, g, 0xF50F3B14u, 33);
        R1(c, d, a, b, g, h, e, f, 0xEA1E7629u, 34);
        R1(b, c, d, a, f, g, h, e, 0xD43CEC53u, 35);
        R1(a, b, c, d, e, f, g, h, 0xA879D8A7u, 36);
        R1(d, a, b, c, h, e, f, g, 0x50F3B14Fu, 37);
        R1(c, d, a, b, g, h, e, f, 0xA1E7629Eu, 38);
        R1(b, c, d, a, f, g, h, e, 0x43CEC53Du, 39);
        R1(a, b, c, d, e, f, g, h, 0x879D8A7Au, 40);
        R1(d, a, b, c, h, e, f, g, 0x0F3B14F5u, 41);
        R1(c, d, a, b, g, h, e, f, 0x1E7629EAu, 42);
        R1(b, c, d, a, f, g, h, e, 0x3CEC53D4u, 43);
        R1(a, b, c, d, e, f, g, h, 0x79D8A7A8u, 44);
        R1(d, a, b, c, h, e, f, g, 0xF3B14F50u, 45);
        R1(c, d, a, b, g, h, e, f, 0xE7629EA1u, 46);
        R1(b, c, d, a, f, g, h, e, 0xCEC53D43u, 47);
        R1(a, b, c, d, e, f, g, h, 0x9D8A7A87u, 48);
        R1(d, a, b, c, h, e, f, g, 0x3B14F50Fu, 49);
        R1(c, d, a, b, g, h, e, f, 0x7629EA1Eu, 50);
        R1(b, c, d, a, f, g, h, e, 0xEC53D43Cu, 51);
        R1(a, b, c, d, e, f, g, h, 0xD8A7A879u, 52);
        R1(d, a, b, c, h, e, f, g, 0xB14F50F3u, 53);
        R1(c, d, a, b, g, h, e, f, 0x629EA1E7u, 54);
        R1(b, c, d, a, f, g, h, e, 0xC53D43CEu, 55);
        R1(a, b, c, d, e, f, g, h, 0x8A7A879Du, 56);
        R1(d, a, b, c, h, e, f, g, 0x14F50F3Bu, 57);
        R1(c, d, a, b, g, h, e, f, 0x29EA1E76u, 58);
        R1(b, c, d, a, f, g, h, e, 0x53D43CECu, 59);
        R1(a, b, c, d, e, f, g, h, 0xA7A879D8u, 60);
        R1(d, a, b, c, h, e, f, g, 0x4F50F3B1u, 61);
        R1(c, d, a, b, g, h, e, f, 0x9EA1E762u, 62);
        R1(b, c, d, a, f, g, h, e, 0x3D43CEC5u, 63);

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
