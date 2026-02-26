#include "smx.h"
#include <string.h>
#include <stdio.h>

/* ---- internal helpers ---- */

static inline void mul64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo) {
    __uint128_t r = (__uint128_t)a * b;
    *lo = (uint64_t)r;
    *hi = (uint64_t)(r >> 64);
}

static inline uint64_t add64(uint64_t a, uint64_t b, uint64_t ci, uint64_t *co) {
    uint64_t s = a + b;
    uint64_t c1 = (s < a) ? 1 : 0;
    uint64_t r = s + ci;
    uint64_t c2 = (r < s) ? 1 : 0;
    *co = c1 + c2;
    return r;
}

static inline uint64_t sub64(uint64_t a, uint64_t b, uint64_t bi, uint64_t *bo) {
    uint64_t d = a - b;
    uint64_t b1 = (a < b) ? 1 : 0;
    uint64_t r = d - bi;
    uint64_t b2 = (d < bi) ? 1 : 0;
    *bo = b1 + b2;
    return r;
}

static inline int clz64(uint64_t x) {
    if (x == 0) return 64;
    return __builtin_clzll(x);
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

/* ---- public BigInt256 functions ---- */

BigInt256 bigint256_zero(void) {
    BigInt256 r = {{0, 0, 0, 0}};
    return r;
}

BigInt256 bigint256_one(void) {
    BigInt256 r = {{1, 0, 0, 0}};
    return r;
}

BigInt256 bigint256_from_hex(const char *s) {
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    size_t slen = strlen(s);

    /* decode hex to big-endian bytes, pad to 32 */
    uint8_t raw[64];
    size_t byte_len = (slen + 1) / 2;
    if (byte_len > 64) byte_len = 64;
    int odd = slen & 1;
    size_t i;
    for (i = 0; i < byte_len; i++) {
        uint8_t hi = 0, lo;
        if (i == 0 && odd) {
            lo = (uint8_t)hex_nibble(s[0]);
        } else {
            size_t idx = i * 2 - (size_t)odd;
            hi = (uint8_t)hex_nibble(s[idx]);
            lo = (uint8_t)hex_nibble(s[idx + 1]);
        }
        raw[i] = (uint8_t)((hi << 4) | lo);
    }

    uint8_t padded[32];
    memset(padded, 0, 32);
    size_t use = byte_len > 32 ? 32 : byte_len;
    size_t start = 32 - use;
    memcpy(padded + start, raw + (byte_len - use), use);

    return bigint256_from_be_bytes(padded, 32);
}

BigInt256 bigint256_from_be_bytes(const uint8_t *data, size_t len) {
    uint8_t padded[32];
    memset(padded, 0, 32);
    if (len > 32) { data += len - 32; len = 32; }
    memcpy(padded + (32 - len), data, len);

    BigInt256 r;
    int i;
    for (i = 0; i < 4; i++) {
        int off = (3 - i) * 8;
        r.limbs[i] = ((uint64_t)padded[off] << 56) | ((uint64_t)padded[off+1] << 48) |
                     ((uint64_t)padded[off+2] << 40) | ((uint64_t)padded[off+3] << 32) |
                     ((uint64_t)padded[off+4] << 24) | ((uint64_t)padded[off+5] << 16) |
                     ((uint64_t)padded[off+6] << 8)  |  (uint64_t)padded[off+7];
    }
    return r;
}

void bigint256_to_be_bytes(const BigInt256 *a, uint8_t out[32]) {
    int i;
    for (i = 0; i < 4; i++) {
        int off = (3 - i) * 8;
        uint64_t v = a->limbs[i];
        out[off]   = (uint8_t)(v >> 56);
        out[off+1] = (uint8_t)(v >> 48);
        out[off+2] = (uint8_t)(v >> 40);
        out[off+3] = (uint8_t)(v >> 32);
        out[off+4] = (uint8_t)(v >> 24);
        out[off+5] = (uint8_t)(v >> 16);
        out[off+6] = (uint8_t)(v >> 8);
        out[off+7] = (uint8_t)(v);
    }
}

void bigint256_to_hex(const BigInt256 *a, char out[65]) {
    static const char hex_upper[] = "0123456789ABCDEF";
    uint8_t be[32];
    bigint256_to_be_bytes(a, be);
    int i;
    for (i = 0; i < 32; i++) {
        out[i*2]   = hex_upper[be[i] >> 4];
        out[i*2+1] = hex_upper[be[i] & 0x0F];
    }
    out[64] = '\0';
}

void bigint256_to_hex_lower(const BigInt256 *a, char out[65]) {
    static const char hex_lower[] = "0123456789abcdef";
    uint8_t be[32];
    bigint256_to_be_bytes(a, be);
    int i;
    for (i = 0; i < 32; i++) {
        out[i*2]   = hex_lower[be[i] >> 4];
        out[i*2+1] = hex_lower[be[i] & 0x0F];
    }
    out[64] = '\0';
}

int bigint256_is_zero(const BigInt256 *a) {
    return a->limbs[0] == 0 && a->limbs[1] == 0 && a->limbs[2] == 0 && a->limbs[3] == 0;
}

int bigint256_is_one(const BigInt256 *a) {
    return a->limbs[0] == 1 && a->limbs[1] == 0 && a->limbs[2] == 0 && a->limbs[3] == 0;
}

int bigint256_compare(const BigInt256 *a, const BigInt256 *b) {
    int i;
    for (i = 3; i >= 0; i--) {
        if (a->limbs[i] > b->limbs[i]) return 1;
        if (a->limbs[i] < b->limbs[i]) return -1;
    }
    return 0;
}

uint64_t bigint256_add(BigInt256 *r, const BigInt256 *a, const BigInt256 *b) {
    uint64_t carry = 0;
    int i;
    for (i = 0; i < 4; i++) {
        r->limbs[i] = add64(a->limbs[i], b->limbs[i], carry, &carry);
    }
    return carry;
}

uint64_t bigint256_sub(BigInt256 *r, const BigInt256 *a, const BigInt256 *b) {
    uint64_t borrow = 0;
    int i;
    for (i = 0; i < 4; i++) {
        r->limbs[i] = sub64(a->limbs[i], b->limbs[i], borrow, &borrow);
    }
    return borrow;
}

void bigint256_mul(uint64_t r[8], const BigInt256 *a, const BigInt256 *b) {
    int i, j;
    memset(r, 0, 8 * sizeof(uint64_t));
    for (i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (j = 0; j < 4; j++) {
            uint64_t hi, lo;
            mul64(a->limbs[i], b->limbs[j], &hi, &lo);
            uint64_t c1;
            lo = add64(lo, r[i+j], 0, &c1);
            hi += c1;
            uint64_t c2;
            lo = add64(lo, carry, 0, &c2);
            hi += c2;
            r[i+j] = lo;
            carry = hi;
        }
        r[i+4] = carry;
    }
}

void bigint256_mod_add(BigInt256 *r, const BigInt256 *a, const BigInt256 *b, const BigInt256 *m) {
    uint64_t carry = bigint256_add(r, a, b);
    if (carry != 0 || bigint256_compare(r, m) >= 0) {
        bigint256_sub(r, r, m);
    }
}

void bigint256_mod_sub(BigInt256 *r, const BigInt256 *a, const BigInt256 *b, const BigInt256 *m) {
    uint64_t borrow = bigint256_sub(r, a, b);
    if (borrow != 0) {
        bigint256_add(r, r, m);
    }
}

/* ---- generic 512-bit modular reduction ---- */

static int compare_512(const uint64_t a[8], const uint64_t b[8]) {
    int i;
    for (i = 7; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

static void sub_512(uint64_t r[8], const uint64_t a[8], const uint64_t b[8]) {
    uint64_t borrow = 0;
    int i;
    for (i = 0; i < 8; i++) {
        r[i] = sub64(a[i], b[i], borrow, &borrow);
    }
}

static void shift_left_512(uint64_t r[8], const uint64_t value[4], int shift) {
    int i;
    memset(r, 0, 8 * sizeof(uint64_t));
    if (shift == 0) {
        memcpy(r, value, 4 * sizeof(uint64_t));
        return;
    }
    int word_shift = shift / 64;
    unsigned bit_shift = (unsigned)(shift % 64);
    if (bit_shift == 0) {
        for (i = 0; i < 4; i++) {
            if (i + word_shift < 8)
                r[i + word_shift] = value[i];
        }
    } else {
        for (i = 0; i < 4; i++) {
            if (i + word_shift < 8)
                r[i + word_shift] |= value[i] << bit_shift;
            if (i + word_shift + 1 < 8)
                r[i + word_shift + 1] |= value[i] >> (64 - bit_shift);
        }
    }
}

static BigInt256 mod_reduce_512(const uint64_t value[8], const BigInt256 *modulus) {
    uint64_t remainder[8];
    int i;
    memcpy(remainder, value, 8 * sizeof(uint64_t));

    int dividend_bits = 0;
    for (i = 7; i >= 0; i--) {
        if (remainder[i] != 0) {
            dividend_bits = (i + 1) * 64 - clz64(remainder[i]);
            break;
        }
    }

    int modulus_bits = 0;
    for (i = 3; i >= 0; i--) {
        if (modulus->limbs[i] != 0) {
            modulus_bits = (i + 1) * 64 - clz64(modulus->limbs[i]);
            break;
        }
    }

    if (modulus_bits == 0) {
        return bigint256_zero(); /* division by zero guard */
    }

    if (dividend_bits < modulus_bits) {
        BigInt256 r;
        memcpy(r.limbs, remainder, 4 * sizeof(uint64_t));
        return r;
    }

    int shift_amount = dividend_bits - modulus_bits;
    int shift;
    for (shift = shift_amount; shift >= 0; shift--) {
        uint64_t shifted[8];
        shift_left_512(shifted, modulus->limbs, shift);
        if (compare_512(remainder, shifted) >= 0) {
            sub_512(remainder, remainder, shifted);
        }
    }

    BigInt256 r;
    memcpy(r.limbs, remainder, 4 * sizeof(uint64_t));
    return r;
}

void bigint256_mod_mul(BigInt256 *r, const BigInt256 *a, const BigInt256 *b, const BigInt256 *m) {
    uint64_t product[8];
    bigint256_mul(product, a, b);
    *r = mod_reduce_512(product, m);
}

void bigint256_mod_pow(BigInt256 *r, const BigInt256 *base, const BigInt256 *exp, const BigInt256 *m) {
    if (bigint256_is_zero(exp)) {
        *r = bigint256_one();
        return;
    }
    BigInt256 result = bigint256_one();
    BigInt256 b2 = *base;
    int bit_len = bigint256_bit_length(exp);
    int i;
    for (i = 0; i < bit_len; i++) {
        if (bigint256_get_bit(exp, i)) {
            bigint256_mod_mul(&result, &result, &b2, m);
        }
        bigint256_mod_mul(&b2, &b2, &b2, m);
    }
    *r = result;
}

void bigint256_mod_inverse(BigInt256 *r, const BigInt256 *a, const BigInt256 *m) {
    BigInt256 two = {{2, 0, 0, 0}};
    BigInt256 pm2;
    bigint256_sub(&pm2, m, &two);
    bigint256_mod_pow(r, a, &pm2, m);
}

/* ---- SM2 fast Solinas reduction ---- */

/* SM2 prime: p = 2^256 - 2^224 - 2^96 + 2^64 - 1 */
static const BigInt256 sm2p = {{
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL
}};

static BigInt256 sm2_mod_reduce_p(const uint64_t c[8]) {
    /* extract 32-bit words, little-endian */
    #define W(i) ((int64_t)((i) % 2 == 0 ? (c[(i)/2] & 0xFFFFFFFF) : (c[(i)/2] >> 32)))

    static const int64_t R[8][8] = {
        { 1, 0,-1, 1, 0, 0, 0, 1},
        { 1, 1,-1, 0, 1, 0, 0, 1},
        { 1, 1, 0, 0, 0, 1, 0, 1},
        { 1, 1, 0, 1, 0, 0, 1, 1},
        { 1, 1, 0, 1, 1, 0, 0, 2},
        { 2, 1,-1, 2, 1, 1, 0, 2},
        { 2, 2,-1, 1, 2, 1, 1, 2},
        { 2, 2, 0, 1, 1, 2, 1, 3},
    };

    int64_t acc[9];
    int i, j;
    memset(acc, 0, sizeof(acc));

    for (j = 0; j < 8; j++) {
        acc[j] = W(j);
        for (i = 0; i < 8; i++) {
            acc[j] += W(i + 8) * R[i][j];
        }
    }

    /* propagate carries (32-bit words) */
    for (i = 0; i < 8; i++) {
        int64_t carry = acc[i] >> 32;
        acc[i] &= 0xFFFFFFFF;
        acc[i+1] += carry;
    }

    /* handle overflow */
    int64_t overflow = acc[8];
    if (overflow != 0) {
        acc[0] += overflow;
        acc[2] -= overflow;
        acc[3] += overflow;
        acc[7] += overflow;
        acc[8] = 0;
        for (i = 0; i < 8; i++) {
            int64_t carry = acc[i] >> 32;
            acc[i] &= 0xFFFFFFFF;
            acc[i+1] += carry;
        }
        int64_t overflow2 = acc[8];
        if (overflow2 != 0) {
            acc[0] += overflow2;
            acc[2] -= overflow2;
            acc[3] += overflow2;
            acc[7] += overflow2;
            acc[8] = 0;
            for (i = 0; i < 8; i++) {
                int64_t carry = acc[i] >> 32;
                acc[i] &= 0xFFFFFFFF;
                acc[i+1] += carry;
            }
        }
    }

    /* handle negative values */
    for (i = 0; i < 8; i++) {
        while (acc[i] < 0) {
            acc[i] += (int64_t)0x100000000LL;
            acc[i+1] -= 1;
        }
    }

    BigInt256 result;
    result.limbs[0] = (uint64_t)acc[0] | ((uint64_t)acc[1] << 32);
    result.limbs[1] = (uint64_t)acc[2] | ((uint64_t)acc[3] << 32);
    result.limbs[2] = (uint64_t)acc[4] | ((uint64_t)acc[5] << 32);
    result.limbs[3] = (uint64_t)acc[6] | ((uint64_t)acc[7] << 32);

    while (bigint256_compare(&result, &sm2p) >= 0) {
        bigint256_sub(&result, &result, &sm2p);
    }
    return result;

    #undef W
}

void bigint256_sm2_mod_mul_p(BigInt256 *r, const BigInt256 *a, const BigInt256 *b) {
    uint64_t product[8];
    bigint256_mul(product, a, b);
    *r = sm2_mod_reduce_p(product);
}

void bigint256_sm2_mod_square_p(BigInt256 *r, const BigInt256 *a) {
    uint64_t product[8];
    bigint256_mul(product, a, a);
    *r = sm2_mod_reduce_p(product);
}

int bigint256_get_bit(const BigInt256 *a, int i) {
    if (i >= 256) return 0;
    int word = i / 64;
    unsigned bit = (unsigned)(i % 64);
    return (int)((a->limbs[word] >> bit) & 1);
}

int bigint256_bit_length(const BigInt256 *a) {
    int i;
    for (i = 3; i >= 0; i--) {
        if (a->limbs[i] != 0) {
            return (i + 1) * 64 - clz64(a->limbs[i]);
        }
    }
    return 0;
}

void bigint256_and(BigInt256 *r, const BigInt256 *a, const BigInt256 *b) {
    int i;
    for (i = 0; i < 4; i++) r->limbs[i] = a->limbs[i] & b->limbs[i];
}

/* ---- Utility functions ---- */

void bytes_to_hex(const uint8_t *data, size_t len, char *out) {
    static const char hex_lower[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) {
        out[i*2]   = hex_lower[data[i] >> 4];
        out[i*2+1] = hex_lower[data[i] & 0x0F];
    }
    out[len*2] = '\0';
}

int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len) {
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
    size_t hex_len = strlen(hex);
    size_t byte_len = hex_len / 2;
    if (byte_len > max_len) return -1;
    size_t i;
    for (i = 0; i < byte_len; i++) {
        out[i] = (uint8_t)((hex_nibble(hex[i*2]) << 4) | hex_nibble(hex[i*2+1]));
    }
    return (int)byte_len;
}
