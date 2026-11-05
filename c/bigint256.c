#include "sm2_fp.h"
#include "smx_internal.h"
#include <string.h>

#ifdef SMX_HAVE_SSE2
#include <emmintrin.h>
#endif

/*
 * Generic BigInt256 API. Comparison, add, sub, mod_add, mod_sub and the hex
 * conversions are branch-free. bigint256_mod_mul, bigint256_mod_pow and
 * bigint256_mod_inverse work for arbitrary moduli and are variable time, as they
 * always were; the SM2 code paths do not use them.
 */

/* ---- hex ---- */

/* n in [0, 15] to its ASCII digit, without a branch or a table. */
static inline char hex_digit(unsigned n, unsigned alpha_delta) {
    unsigned letter = 0u - ((9u - n) >> 31);
    return (char)(n + '0' + (letter & alpha_delta));
}

void smx_hex_encode(const uint8_t *data, size_t len, char *out, char alpha) {
    const unsigned delta = (unsigned)alpha - '0' - 10u;
    size_t i = 0;

#ifdef SMX_HAVE_SSE2
    const __m128i low_mask = _mm_set1_epi8(0x0F);
    const __m128i nine = _mm_set1_epi8(9);
    const __m128i zero_char = _mm_set1_epi8('0');
    const __m128i letter_delta = _mm_set1_epi8((char)delta);
    for (; len - i >= 16; i += 16) {
        __m128i x = _mm_loadu_si128((const __m128i *)(const void *)(data + i));
        __m128i hi = _mm_and_si128(_mm_srli_epi16(x, 4), low_mask);
        __m128i lo = _mm_and_si128(x, low_mask);
        __m128i a = _mm_unpacklo_epi8(hi, lo);
        __m128i b = _mm_unpackhi_epi8(hi, lo);
        a = _mm_add_epi8(_mm_add_epi8(a, zero_char),
                         _mm_and_si128(_mm_cmpgt_epi8(a, nine), letter_delta));
        b = _mm_add_epi8(_mm_add_epi8(b, zero_char),
                         _mm_and_si128(_mm_cmpgt_epi8(b, nine), letter_delta));
        _mm_storeu_si128((__m128i *)(void *)(out + i * 2), a);
        _mm_storeu_si128((__m128i *)(void *)(out + i * 2 + 16), b);
    }
#endif
    for (; i < len; i++) {
        out[i * 2] = hex_digit((unsigned)data[i] >> 4, delta);
        out[i * 2 + 1] = hex_digit((unsigned)data[i] & 15u, delta);
    }
}

/* ASCII hex digit to its value; anything else maps to 0. No branch or table. */
static inline unsigned hex_nibble(char ch) {
    unsigned c = (unsigned char)ch;
    unsigned d = c - '0';
    unsigned l = (c | 0x20u) - 'a';
    unsigned is_digit = 0u - (((d - 10u) & ~d) >> 31);
    unsigned is_letter = 0u - (((l - 6u) & ~l) >> 31);
    return (d & is_digit) | ((l + 10u) & is_letter);
}

void smx_hex_decode(const char *hex, size_t len, uint8_t *out) {
    size_t i = 0;

#ifdef SMX_HAVE_SSE2
    /* Signed compares: bytes >= 0x80 are negative, so they fail both range tests. */
    const __m128i below_0 = _mm_set1_epi8('0' - 1), above_9 = _mm_set1_epi8('9' + 1);
    const __m128i below_a = _mm_set1_epi8('a' - 1), above_f = _mm_set1_epi8('f' + 1);
    const __m128i zero_char = _mm_set1_epi8('0'), lower = _mm_set1_epi8(0x20);
    const __m128i letter_base = _mm_set1_epi8('a' - 10);
    const __m128i word_low = _mm_set1_epi16(0x00FF);
#define SMX_NIBBLES(v)                                                                             \
    _mm_or_si128(                                                                                  \
        _mm_and_si128(_mm_and_si128(_mm_cmpgt_epi8(v, below_0), _mm_cmpgt_epi8(above_9, v)),       \
                      _mm_sub_epi8(v, zero_char)),                                                 \
        _mm_and_si128(_mm_and_si128(_mm_cmpgt_epi8(_mm_or_si128(v, lower), below_a),               \
                                    _mm_cmpgt_epi8(above_f, _mm_or_si128(v, lower))),              \
                      _mm_sub_epi8(_mm_or_si128(v, lower), letter_base)))
    for (; len - i >= 16; i += 16) {
        __m128i a = _mm_loadu_si128((const __m128i *)(const void *)(hex + i * 2));
        __m128i b = _mm_loadu_si128((const __m128i *)(const void *)(hex + i * 2 + 16));
        __m128i na = SMX_NIBBLES(a);
        __m128i nb = SMX_NIBBLES(b);
        /* each 16-bit word holds (first char, second char); make (first << 4) | second */
        na = _mm_and_si128(_mm_or_si128(_mm_slli_epi16(na, 4), _mm_srli_epi16(na, 8)), word_low);
        nb = _mm_and_si128(_mm_or_si128(_mm_slli_epi16(nb, 4), _mm_srli_epi16(nb, 8)), word_low);
        _mm_storeu_si128((__m128i *)(void *)(out + i), _mm_packus_epi16(na, nb));
    }
#undef SMX_NIBBLES
#endif
    for (; i < len; i++) {
        out[i] = (uint8_t)((hex_nibble(hex[i * 2]) << 4) | hex_nibble(hex[i * 2 + 1]));
    }
}

void bytes_to_hex(const uint8_t *data, size_t len, char *out) {
    smx_hex_encode(data, len, out, 'a');
    out[len * 2] = '\0';
}

int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len) {
    size_t byte_len;
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
    }
    byte_len = strlen(hex) / 2;
    if (byte_len > max_len) {
        return -1;
    }
    smx_hex_decode(hex, byte_len, out);
    return (int)byte_len;
}

/* ---- construction and conversion ---- */

BigInt256 bigint256_zero(void) {
    BigInt256 r = {{0, 0, 0, 0}};
    return r;
}

BigInt256 bigint256_one(void) {
    BigInt256 r = {{1, 0, 0, 0}};
    return r;
}

/*
 * Accepts an optional 0x prefix and any length. An odd length has an implied
 * leading zero. At most the first 64 bytes of a longer string are considered, and
 * of those the last 32 bytes form the value.
 */
BigInt256 bigint256_from_hex(const char *s) {
    BigInt256 r = {{0, 0, 0, 0}};
    size_t slen, byte_len, end, start, i;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }
    slen = strlen(s);
    byte_len = (slen + 1) / 2;
    if (byte_len > 64) {
        byte_len = 64;
    }
    end = byte_len * 2 - (slen & 1);
    start = end > 64 ? end - 64 : 0;
    for (i = start; i < end; i++) {
        size_t pos = end - 1 - i; /* nibble index from the least significant end */
        r.limbs[pos / 16] |= (uint64_t)hex_nibble(s[i]) << ((pos % 16) * 4);
    }
    return r;
}

BigInt256 bigint256_from_be_bytes(const uint8_t *data, size_t len) {
    uint8_t padded[32];
    BigInt256 r;
    if (len >= 32) {
        data += len - 32;
    } else {
        memset(padded, 0, 32 - len);
        if (len > 0) {
            memcpy(padded + (32 - len), data, len);
        }
        data = padded;
    }
    r.limbs[3] = smx_load_be64(data);
    r.limbs[2] = smx_load_be64(data + 8);
    r.limbs[1] = smx_load_be64(data + 16);
    r.limbs[0] = smx_load_be64(data + 24);
    return r;
}

void bigint256_to_be_bytes(const BigInt256 *a, uint8_t out[32]) {
    smx_store_be64(out, a->limbs[3]);
    smx_store_be64(out + 8, a->limbs[2]);
    smx_store_be64(out + 16, a->limbs[1]);
    smx_store_be64(out + 24, a->limbs[0]);
}

void bigint256_to_hex(const BigInt256 *a, char out[65]) {
    uint8_t be[32];
    bigint256_to_be_bytes(a, be);
    smx_hex_encode(be, 32, out, 'A');
    out[64] = '\0';
}

void bigint256_to_hex_lower(const BigInt256 *a, char out[65]) {
    uint8_t be[32];
    bigint256_to_be_bytes(a, be);
    smx_hex_encode(be, 32, out, 'a');
    out[64] = '\0';
}

/* ---- comparison and bits ---- */

int bigint256_is_zero(const BigInt256 *a) {
    return (a->limbs[0] | a->limbs[1] | a->limbs[2] | a->limbs[3]) == 0;
}

int bigint256_is_one(const BigInt256 *a) {
    return ((a->limbs[0] ^ 1) | a->limbs[1] | a->limbs[2] | a->limbs[3]) == 0;
}

int bigint256_compare(const BigInt256 *a, const BigInt256 *b) {
    uint64_t lt = 0, gt = 0;
    int i;
    for (i = 0; i < 4; i++) {
        (void)smx_subb(a->limbs[i], b->limbs[i], lt, &lt);
        (void)smx_subb(b->limbs[i], a->limbs[i], gt, &gt);
    }
    return (int)gt - (int)lt;
}

int bigint256_get_bit(const BigInt256 *a, int i) {
    if (i >= 256) {
        return 0;
    }
    return (int)((a->limbs[i / 64] >> (i % 64)) & 1);
}

static inline int clz64(uint64_t x) {
#if defined(__GNUC__)
    return __builtin_clzll(x);
#else
    int n = 0;
    while ((x & ((uint64_t)1 << 63)) == 0) {
        x <<= 1;
        n++;
    }
    return n;
#endif
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
    for (i = 0; i < 4; i++) {
        r->limbs[i] = a->limbs[i] & b->limbs[i];
    }
}

/* ---- add, sub, mul ---- */

uint64_t bigint256_add(BigInt256 *r, const BigInt256 *a, const BigInt256 *b) {
    uint64_t c;
    r->limbs[0] = smx_addc(a->limbs[0], b->limbs[0], 0, &c);
    r->limbs[1] = smx_addc(a->limbs[1], b->limbs[1], c, &c);
    r->limbs[2] = smx_addc(a->limbs[2], b->limbs[2], c, &c);
    r->limbs[3] = smx_addc(a->limbs[3], b->limbs[3], c, &c);
    return c;
}

uint64_t bigint256_sub(BigInt256 *r, const BigInt256 *a, const BigInt256 *b) {
    uint64_t c;
    r->limbs[0] = smx_subb(a->limbs[0], b->limbs[0], 0, &c);
    r->limbs[1] = smx_subb(a->limbs[1], b->limbs[1], c, &c);
    r->limbs[2] = smx_subb(a->limbs[2], b->limbs[2], c, &c);
    r->limbs[3] = smx_subb(a->limbs[3], b->limbs[3], c, &c);
    return c;
}

void bigint256_mul(uint64_t r[8], const BigInt256 *a, const BigInt256 *b) {
    uint64_t t[8];
    smx_mul_4x4(t, a->limbs, b->limbs);
    memcpy(r, t, sizeof(t));
}

void bigint256_mod_add(BigInt256 *r, const BigInt256 *a, const BigInt256 *b, const BigInt256 *m) {
    BigInt256 sum, reduced;
    uint64_t carry = bigint256_add(&sum, a, b);
    uint64_t borrow = bigint256_sub(&reduced, &sum, m);
    uint64_t keep = (uint64_t)0 - (borrow & (carry ^ 1));
    int i;
    for (i = 0; i < 4; i++) {
        r->limbs[i] = reduced.limbs[i] ^ (keep & (reduced.limbs[i] ^ sum.limbs[i]));
    }
}

void bigint256_mod_sub(BigInt256 *r, const BigInt256 *a, const BigInt256 *b, const BigInt256 *m) {
    BigInt256 diff, mm;
    uint64_t mask = (uint64_t)0 - bigint256_sub(&diff, a, b);
    int i;
    for (i = 0; i < 4; i++) {
        mm.limbs[i] = m->limbs[i] & mask;
    }
    bigint256_add(r, &diff, &mm);
}

/* ---- generic modular reduction: Knuth algorithm D on 32-bit digits ---- */

static BigInt256 mod_reduce_512(const uint64_t value[8], const BigInt256 *modulus) {
    uint32_t u[17], v[8], rem[8];
    BigInt256 r;
    int n = 8, m = 16;
    int shift, i, j;

    while (n > 0 && ((modulus->limbs[(n - 1) / 2] >> (((n - 1) & 1) * 32)) & 0xFFFFFFFFu) == 0) {
        n--;
    }
    if (n == 0) {
        return bigint256_zero(); /* division by zero guard */
    }
    for (i = 0; i < 8; i++) {
        v[i] = (uint32_t)(modulus->limbs[i / 2] >> ((i & 1) * 32));
    }
    for (i = 0; i < 16; i++) {
        u[i] = (uint32_t)(value[i / 2] >> ((i & 1) * 32));
    }
    while (m > 0 && u[m - 1] == 0) {
        m--;
    }
    if (m < n) {
        memcpy(r.limbs, value, sizeof(r.limbs));
        return r;
    }

    /* normalize so that the divisor's top bit is set */
    shift = clz64((uint64_t)v[n - 1]) - 32;
    u[m] = 0;
    if (shift != 0) {
        for (i = n - 1; i > 0; i--) {
            v[i] = (v[i] << shift) | (v[i - 1] >> (32 - shift));
        }
        v[0] <<= shift;
        u[m] = u[m - 1] >> (32 - shift);
        for (i = m - 1; i > 0; i--) {
            u[i] = (u[i] << shift) | (u[i - 1] >> (32 - shift));
        }
        u[0] <<= shift;
    }

    for (j = m - n; j >= 0; j--) {
        uint64_t num = ((uint64_t)u[j + n] << 32) | u[j + n - 1];
        uint64_t qhat, rhat, borrow = 0, carry = 0;
        int64_t top;

        if (n == 1) {
            /* single digit divisor: the quotient digit is exact */
            qhat = num / v[0];
            u[j + 1] = 0;
            u[j] = (uint32_t)(num - qhat * v[0]);
            continue;
        }

        qhat = num / v[n - 1];
        rhat = num - qhat * v[n - 1];
        while (qhat >> 32 != 0 || qhat * v[n - 2] > ((rhat << 32) | u[j + n - 2])) {
            qhat--;
            rhat += v[n - 1];
            if (rhat >> 32 != 0) {
                break;
            }
        }

        for (i = 0; i < n; i++) {
            uint64_t p = qhat * v[i] + carry;
            uint64_t d = (uint64_t)u[i + j] - (p & 0xFFFFFFFFu) - borrow;
            carry = p >> 32;
            u[i + j] = (uint32_t)d;
            borrow = (d >> 32) & 1;
        }
        top = (int64_t)((uint64_t)u[j + n] - carry - borrow);
        u[j + n] = (uint32_t)top;

        if (top < 0) {
            /* qhat was one too large: add the divisor back */
            uint64_t c = 0;
            for (i = 0; i < n; i++) {
                uint64_t t = (uint64_t)u[i + j] + v[i] + c;
                u[i + j] = (uint32_t)t;
                c = t >> 32;
            }
            u[j + n] += (uint32_t)c;
        }
    }

    /* denormalize the remainder */
    memset(rem, 0, sizeof(rem));
    for (i = 0; i < n; i++) {
        rem[i] =
            shift != 0 ? (u[i] >> shift) | (uint32_t)((uint64_t)u[i + 1] << (32 - shift)) : u[i];
    }
    for (i = 0; i < 4; i++) {
        r.limbs[i] = (uint64_t)rem[i * 2] | ((uint64_t)rem[i * 2 + 1] << 32);
    }
    return r;
}

void bigint256_mod_mul(BigInt256 *r, const BigInt256 *a, const BigInt256 *b, const BigInt256 *m) {
    uint64_t product[8];
    smx_mul_4x4(product, a->limbs, b->limbs);
    *r = mod_reduce_512(product, m);
}

/* Left-to-right with a fixed 4-bit window. */
void bigint256_mod_pow(BigInt256 *r, const BigInt256 *base, const BigInt256 *exp,
                       const BigInt256 *m) {
    BigInt256 table[16], result;
    int bits = bigint256_bit_length(exp);
    int i, top;

    if (bits == 0) {
        *r = bigint256_one();
        return;
    }
    table[1] = *base;
    for (i = 2; i < 16; i++) {
        bigint256_mod_mul(&table[i], &table[i - 1], base, m);
    }
    top = (bits - 1) / 4 * 4;
    result = bigint256_one();
    for (i = top; i >= 0; i -= 4) {
        unsigned digit = (unsigned)(exp->limbs[i / 64] >> (i % 64)) & 15u;
        if (i != top) {
            int j;
            for (j = 0; j < 4; j++) {
                bigint256_mod_mul(&result, &result, &result, m);
            }
        }
        if (digit != 0) {
            bigint256_mod_mul(&result, &result, &table[digit], m);
        }
    }
    *r = result;
}

void bigint256_mod_inverse(BigInt256 *r, const BigInt256 *a, const BigInt256 *m) {
    BigInt256 two = {{2, 0, 0, 0}};
    BigInt256 exponent;
    bigint256_sub(&exponent, m, &two);
    bigint256_mod_pow(r, a, &exponent, m);
}

/* ---- SM2 prime ---- */

void bigint256_sm2_mod_mul_p(BigInt256 *r, const BigInt256 *a, const BigInt256 *b) {
    fe_mul(r->limbs, a->limbs, b->limbs);
}

void bigint256_sm2_mod_square_p(BigInt256 *r, const BigInt256 *a) {
    fe_sqr(r->limbs, a->limbs);
}
