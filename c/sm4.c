#include "smx.h"
#include <stdlib.h>
#include <string.h>

static const uint8_t sm4_sbox[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48,
};

static const uint32_t sm4_fk[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

static const uint32_t sm4_ck[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
    0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
    0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
    0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
    0x10171e25,0x2c333a41,0x484f565d,0x646b7279,
};

static inline uint32_t sm4_rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t sm4_tau(uint32_t a) {
    return ((uint32_t)sm4_sbox[(uint8_t)(a >> 24)] << 24) |
           ((uint32_t)sm4_sbox[(uint8_t)(a >> 16)] << 16) |
           ((uint32_t)sm4_sbox[(uint8_t)(a >> 8)]  << 8)  |
            (uint32_t)sm4_sbox[(uint8_t)(a)];
}

static uint32_t sm4_l(uint32_t b) {
    return b ^ sm4_rotl32(b, 2) ^ sm4_rotl32(b, 10) ^ sm4_rotl32(b, 18) ^ sm4_rotl32(b, 24);
}

static uint32_t sm4_t(uint32_t a) {
    return sm4_l(sm4_tau(a));
}

static uint32_t sm4_t_prime(uint32_t a) {
    uint32_t b = sm4_tau(a);
    return b ^ sm4_rotl32(b, 13) ^ sm4_rotl32(b, 23);
}

static uint32_t sm4_f(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) {
    return x0 ^ sm4_t(x1 ^ x2 ^ x3 ^ rk);
}

/* prepare key: if not 16 bytes, hash with SM3 and take first 16 hex chars */
static void sm4_prepare_key(const uint8_t *input, size_t len, uint8_t out[16]) {
    if (len == 16) {
        memcpy(out, input, 16);
        return;
    }
    SM3 h;
    sm3_init(&h);
    sm3_update(&h, input, len);
    sm3_finish(&h);
    /* take first 16 characters of uppercase hex as key bytes */
    memcpy(out, h.hash_hex, 16);
}

static void sm4_init_key(SM4 *ctx, const uint8_t key[16], const uint8_t iv[16]) {
    uint32_t mk[4], k[36];
    int i;

    for (i = 0; i < 4; i++) {
        mk[i] = ((uint32_t)key[i*4] << 24) | ((uint32_t)key[i*4+1] << 16) |
                 ((uint32_t)key[i*4+2] << 8) | (uint32_t)key[i*4+3];
    }

    k[0] = mk[0] ^ sm4_fk[0];
    k[1] = mk[1] ^ sm4_fk[1];
    k[2] = mk[2] ^ sm4_fk[2];
    k[3] = mk[3] ^ sm4_fk[3];

    for (i = 0; i < 32; i++) {
        uint32_t input = k[i+1] ^ k[i+2] ^ k[i+3] ^ sm4_ck[i];
        k[i+4] = k[i] ^ sm4_t_prime(input);
        ctx->rk[i] = k[i+4];
    }

    memcpy(ctx->iv, iv, 16);
}

static void sm4_cbc_encrypt_block(const SM4 *ctx, const uint8_t block[16],
                                   const uint8_t iv[16], uint8_t out[16]) {
    uint32_t x[4], xn[36];
    int i;

    for (i = 0; i < 4; i++) {
        uint32_t bw = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
                      ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
        uint32_t iw = ((uint32_t)iv[i*4] << 24) | ((uint32_t)iv[i*4+1] << 16) |
                      ((uint32_t)iv[i*4+2] << 8) | (uint32_t)iv[i*4+3];
        x[i] = bw ^ iw;
    }

    memcpy(xn, x, 4 * sizeof(uint32_t));
    for (i = 0; i < 32; i++) {
        xn[i+4] = sm4_f(xn[i], xn[i+1], xn[i+2], xn[i+3], ctx->rk[i]);
    }

    /* reverse */
    uint32_t xo[4] = {xn[35], xn[34], xn[33], xn[32]};
    for (i = 0; i < 4; i++) {
        out[i*4]   = (uint8_t)(xo[i] >> 24);
        out[i*4+1] = (uint8_t)(xo[i] >> 16);
        out[i*4+2] = (uint8_t)(xo[i] >> 8);
        out[i*4+3] = (uint8_t)(xo[i]);
    }
}

static void sm4_cbc_decrypt_block(const SM4 *ctx, const uint8_t block[16],
                                   const uint8_t iv[16], uint8_t out[16]) {
    uint32_t x[4], xn[36];
    int i;

    for (i = 0; i < 4; i++) {
        x[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    }

    memcpy(xn, x, 4 * sizeof(uint32_t));
    for (i = 0; i < 32; i++) {
        xn[i+4] = sm4_f(xn[i], xn[i+1], xn[i+2], xn[i+3], ctx->rk[31-i]);
    }

    uint32_t xo[4] = {xn[35], xn[34], xn[33], xn[32]};
    for (i = 0; i < 4; i++) {
        uint8_t b[4];
        b[0] = (uint8_t)(xo[i] >> 24);
        b[1] = (uint8_t)(xo[i] >> 16);
        b[2] = (uint8_t)(xo[i] >> 8);
        b[3] = (uint8_t)(xo[i]);
        out[i*4]   = b[0] ^ iv[i*4];
        out[i*4+1] = b[1] ^ iv[i*4+1];
        out[i*4+2] = b[2] ^ iv[i*4+2];
        out[i*4+3] = b[3] ^ iv[i*4+3];
    }
}

static size_t pkcs7_pad(const uint8_t *input, size_t len, uint8_t **out) {
    int pad_len = 16 - (int)(len % 16);
    if (pad_len == 0) pad_len = 16;
    size_t total = len + (size_t)pad_len;
    *out = (uint8_t *)malloc(total);
    memcpy(*out, input, len);
    memset(*out + len, (uint8_t)pad_len, (size_t)pad_len);
    return total;
}

static int pkcs7_unpad(const uint8_t *input, size_t len, size_t *out_len) {
    if (len == 0) { *out_len = 0; return 0; }
    int pad_len = (int)input[len - 1];
    if (pad_len == 0 || pad_len > 16 || (size_t)pad_len > len) return -1;
    size_t i;
    for (i = len - (size_t)pad_len; i < len; i++) {
        if ((int)input[i] != pad_len) return -1;
    }
    *out_len = len - (size_t)pad_len;
    return 0;
}

void sm4_init(SM4 *ctx) {
    memset(ctx, 0, sizeof(SM4));
}

void sm4_set_key(SM4 *ctx, const uint8_t *key, size_t key_len,
                  const uint8_t *iv, size_t iv_len) {
    uint8_t key_bytes[16], iv_bytes[16];
    sm4_prepare_key(key, key_len, key_bytes);
    sm4_prepare_key(iv, iv_len, iv_bytes);
    sm4_init_key(ctx, key_bytes, iv_bytes);
}

char *sm4_encrypt(SM4 *ctx, const char *plaintext) {
    size_t input_len = strlen(plaintext);
    uint8_t *padded;
    size_t padded_len = pkcs7_pad((const uint8_t *)plaintext, input_len, &padded);

    uint8_t *output = (uint8_t *)malloc(padded_len);
    uint8_t cur_iv[16];
    memcpy(cur_iv, ctx->iv, 16);

    size_t i;
    for (i = 0; i < padded_len; i += 16) {
        sm4_cbc_encrypt_block(ctx, padded + i, cur_iv, output + i);
        memcpy(cur_iv, output + i, 16);
    }
    free(padded);

    char *hex = (char *)malloc(padded_len * 2 + 1);
    bytes_to_hex(output, padded_len, hex);
    free(output);
    return hex;
}

char *sm4_decrypt(SM4 *ctx, const char *ciphertext_hex) {
    size_t hex_len = strlen(ciphertext_hex);
    size_t byte_len = hex_len / 2;
    if (byte_len % 16 != 0) return NULL;

    uint8_t *input = (uint8_t *)malloc(byte_len);
    hex_to_bytes(ciphertext_hex, input, byte_len);

    uint8_t *output = (uint8_t *)malloc(byte_len);
    uint8_t cur_iv[16];
    memcpy(cur_iv, ctx->iv, 16);

    size_t i;
    for (i = 0; i < byte_len; i += 16) {
        sm4_cbc_decrypt_block(ctx, input + i, cur_iv, output + i);
        memcpy(cur_iv, input + i, 16);
    }
    free(input);

    size_t unpadded_len;
    if (pkcs7_unpad(output, byte_len, &unpadded_len) != 0) {
        free(output);
        return NULL;
    }

    char *result = (char *)malloc(unpadded_len + 1);
    memcpy(result, output, unpadded_len);
    result[unpadded_len] = '\0';
    free(output);
    return result;
}
