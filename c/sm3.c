#include "smx.h"
#include <string.h>

static const uint32_t sm3_iv[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
};

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static inline uint32_t sm3_ff1(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (x & z) | (y & z);
}

static inline uint32_t sm3_gg1(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (~x & z);
}

static inline uint32_t sm3_p0(uint32_t x) {
    return x ^ rotl32(x, 9) ^ rotl32(x, 17);
}

static inline uint32_t sm3_p1(uint32_t x) {
    return x ^ rotl32(x, 15) ^ rotl32(x, 23);
}

static void sm3_process_block(SM3 *ctx, const uint8_t block[64]) {
    uint32_t w[68], w2[64];
    int j;

    /* message expansion */
    for (j = 0; j < 16; j++) {
        int off = j * 4;
        w[j] = ((uint32_t)block[off] << 24) | ((uint32_t)block[off+1] << 16) |
               ((uint32_t)block[off+2] << 8) | (uint32_t)block[off+3];
    }
    for (j = 16; j < 68; j++) {
        uint32_t r15 = rotl32(w[j-3], 15);
        uint32_t r7  = rotl32(w[j-13], 7);
        w[j] = sm3_p1(w[j-16] ^ w[j-9] ^ r15) ^ r7 ^ w[j-6];
    }
    for (j = 0; j < 64; j++) {
        w2[j] = w[j] ^ w[j+4];
    }

    /* compression */
    uint32_t a = ctx->v[0], b = ctx->v[1], c = ctx->v[2], d = ctx->v[3];
    uint32_t e = ctx->v[4], f = ctx->v[5], g = ctx->v[6], h = ctx->v[7];

    for (j = 0; j < 64; j++) {
        uint32_t a12 = rotl32(a, 12);
        uint32_t tj;
        if (j < 16)
            tj = rotl32(0x79CC4519, j);
        else
            tj = rotl32(0x7A879D8A, j % 32);
        uint32_t ss = a12 + e + tj;
        uint32_t ss1 = rotl32(ss, 7);
        uint32_t ss2 = ss1 ^ a12;

        uint32_t tt1, tt2;
        if (j < 16) {
            tt1 = (a ^ b ^ c) + d + ss2 + w2[j];
            tt2 = (e ^ f ^ g) + h + ss1 + w[j];
        } else {
            tt1 = sm3_ff1(a, b, c) + d + ss2 + w2[j];
            tt2 = sm3_gg1(e, f, g) + h + ss1 + w[j];
        }
        d = c;
        c = rotl32(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = rotl32(f, 19);
        f = e;
        e = sm3_p0(tt2);
    }

    ctx->v[0] ^= a;
    ctx->v[1] ^= b;
    ctx->v[2] ^= c;
    ctx->v[3] ^= d;
    ctx->v[4] ^= e;
    ctx->v[5] ^= f;
    ctx->v[6] ^= g;
    ctx->v[7] ^= h;
}

static void sm3_generate_hash(SM3 *ctx) {
    static const char hex_upper[] = "0123456789ABCDEF";
    uint8_t out[32];
    int i, off = 0;
    for (i = 0; i < 8; i++) {
        uint32_t v = ctx->v[i];
        out[off]   = (uint8_t)(v >> 24);
        out[off+1] = (uint8_t)(v >> 16);
        out[off+2] = (uint8_t)(v >> 8);
        out[off+3] = (uint8_t)(v);
        off += 4;
    }
    memcpy(ctx->hash_bytes, out, 32);
    for (i = 0; i < 32; i++) {
        ctx->hash_hex[i*2]   = hex_upper[out[i] >> 4];
        ctx->hash_hex[i*2+1] = hex_upper[out[i] & 0x0F];
    }
    ctx->hash_hex[64] = '\0';
}

void sm3_init(SM3 *ctx) {
    memcpy(ctx->v, sm3_iv, sizeof(sm3_iv));
    ctx->buff_len = 0;
    ctx->data_bits_len = 0;
    memset(ctx->hash_bytes, 0, 32);
    memset(ctx->hash_hex, 0, 65);
}

void sm3_update_byte(SM3 *ctx, uint8_t b) {
    ctx->buff[ctx->buff_len++] = b;
    ctx->data_bits_len += 8;
    if (ctx->buff_len == 64) {
        sm3_process_block(ctx, ctx->buff);
        ctx->buff_len = 0;
    }
}

void sm3_update(SM3 *ctx, const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        sm3_update_byte(ctx, data[i]);
    }
}

void sm3_finish(SM3 *ctx) {
    uint64_t total_bits = ctx->data_bits_len;
    int pos = ctx->buff_len;

    /* append 0x80 */
    ctx->buff[pos++] = 0x80;

    /* if not enough room for 8-byte length, process and start new block */
    if (pos > 56) {
        while (pos < 64) ctx->buff[pos++] = 0;
        sm3_process_block(ctx, ctx->buff);
        pos = 0;
    }

    /* pad with zeros until position 56 */
    while (pos < 56) ctx->buff[pos++] = 0;

    /* append 64-bit length in big-endian */
    int i;
    for (i = 0; i < 8; i++) {
        ctx->buff[56 + i] = (uint8_t)(total_bits >> (56 - i * 8));
    }

    sm3_process_block(ctx, ctx->buff);
    sm3_generate_hash(ctx);

    /* reset for reuse */
    memcpy(ctx->v, sm3_iv, sizeof(sm3_iv));
    ctx->buff_len = 0;
    ctx->data_bits_len = 0;
}
