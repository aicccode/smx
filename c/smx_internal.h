/*
 * Internal helpers shared by the library's translation units. Not public API.
 *
 * Portability switches (each has a tested fallback, see `make check-fallbacks`):
 *   SMX_NO_INT128  do not use the compiler's 128-bit integer for wide multiply
 *   SMX_NO_SIMD    do not use x86 SIMD, for anything
 */
#ifndef SMX_INTERNAL_H
#define SMX_INTERNAL_H

#include "smx.h"

#if defined(__SIZEOF_INT128__) && !defined(SMX_NO_INT128)
#define SMX_HAVE_INT128 1
__extension__ typedef unsigned __int128 smx_u128;
#endif

/* SSE2 is part of the x86-64 baseline, so it needs no runtime detection. */
#if defined(__x86_64__) && defined(__SSE2__) && defined(__GNUC__) && !defined(SMX_NO_SIMD)
#define SMX_HAVE_SSE2 1
#endif

/* x86-64 carry intrinsics chain into real adc/sbb instead of materializing flags. */
#if defined(__x86_64__) && defined(__GNUC__) && !defined(SMX_NO_SIMD) && !defined(SMX_CT_TEST)
#include <immintrin.h>
#define SMX_HAVE_ADC_INTRINSICS 1
#endif

/*
 * Constant-time verification (test_ct.c, `make check-ct`) builds with
 * MemorySanitizer and marks secrets as uninitialized, so any branch or memory access
 * that depends on them is reported. SMX_DECLASSIFY marks the deliberate exceptions:
 * values that are public, or that only ever differ for invalid input. It expands to
 * nothing in normal builds.
 */
#if defined(SMX_CT_TEST) && defined(__has_feature)
#if __has_feature(memory_sanitizer)
#include <sanitizer/msan_interface.h>
#define SMX_DECLASSIFY(ptr, size) __msan_unpoison((ptr), (size))
#endif
#endif
#ifndef SMX_DECLASSIFY
#define SMX_DECLASSIFY(ptr, size) ((void)0)
#endif

#if defined(__GNUC__)
#define SMX_MAYBE_UNUSED __attribute__((unused))
#define SMX_NOINLINE __attribute__((noinline))
#else
#define SMX_MAYBE_UNUSED
#define SMX_NOINLINE
#endif

/* ---- wide arithmetic ---- */

/* a + b + c, c in {0, 1}; *co receives the carry out. */
static inline uint64_t smx_addc(uint64_t a, uint64_t b, uint64_t c, uint64_t *co) {
#if defined(SMX_HAVE_ADC_INTRINSICS)
    unsigned long long r;
    *co = _addcarry_u64((unsigned char)c, a, b, &r);
    return r;
#elif defined(SMX_HAVE_INT128)
    smx_u128 t = (smx_u128)a + b + c;
    *co = (uint64_t)(t >> 64);
    return (uint64_t)t;
#else
    /* carry from the bits alone: comparisons could compile to branches */
    uint64_t r = a + b + c;
    *co = ((a & b) | ((a | b) & ~r)) >> 63;
    return r;
#endif
}

/* a - b - c, c in {0, 1}; *bo receives the borrow out. */
static inline uint64_t smx_subb(uint64_t a, uint64_t b, uint64_t c, uint64_t *bo) {
#if defined(SMX_HAVE_ADC_INTRINSICS)
    unsigned long long r;
    *bo = _subborrow_u64((unsigned char)c, a, b, &r);
    return r;
#elif defined(SMX_HAVE_INT128)
    smx_u128 t = (smx_u128)a - b - c;
    *bo = (uint64_t)(t >> 64) & 1;
    return (uint64_t)t;
#else
    uint64_t r = a - b - c;
    *bo = ((~a & b) | ((~a | b) & r)) >> 63;
    return r;
#endif
}

/* a * b + t + c, which cannot overflow 128 bits; returns low, *hi receives high. */
static inline uint64_t smx_mac(uint64_t a, uint64_t b, uint64_t t, uint64_t c, uint64_t *hi) {
#ifdef SMX_HAVE_INT128
    smx_u128 w = (smx_u128)a * b + t + c;
    *hi = (uint64_t)(w >> 64);
    return (uint64_t)w;
#else
    uint64_t a0 = a & 0xFFFFFFFFu, a1 = a >> 32;
    uint64_t b0 = b & 0xFFFFFFFFu, b1 = b >> 32;
    uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    uint64_t mid = (p00 >> 32) + (p01 & 0xFFFFFFFFu) + (p10 & 0xFFFFFFFFu);
    uint64_t lo = (p00 & 0xFFFFFFFFu) | (mid << 32);
    uint64_t high = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
    uint64_t k;
    lo = smx_addc(lo, t, 0, &k);
    high += k;
    lo = smx_addc(lo, c, 0, &k);
    *hi = high + k;
    return lo;
#endif
}

/*
 * Hides a value from the optimizer. An optimizer that can see a mask is always 0 or all
 * ones may turn masked code back into a compare and a branch, which skips the very memory
 * accesses the mask exists to keep uniform. This really happened: clang -O3 made the table
 * scan in ec_mul_g skip the loads of every entry but the selected one.
 *
 * So a mask needs a barrier on both sides, as the smx_mask_* helpers below do. Without one on
 * the finished mask, the compiler knows it is 0 or all ones, and can skip the masked work with
 * a branch, as above. Without one on the value it is made from, the compiler can compute it
 * with a branch, which is what happened in the hex tail. It emits no instructions.
 * tools/check_ct_asm.py and test_ct_trace.c check the compiled result.
 *
 * Under SMX_CT_TEST it is the identity, because MemorySanitizer treats any uninitialized
 * operand of an asm statement as an error, and it must be able to track the value through.
 */
static inline uint64_t smx_ct_barrier(uint64_t x) {
#if defined(SMX_CT_TEST)
    return x;
#elif defined(__GNUC__)
    __asm__ __volatile__("" : "+r"(x));
    return x;
#else
    volatile uint64_t v = x;
    return v;
#endif
}

/* All ones if x == 0, otherwise zero. No branches. */
static inline uint64_t smx_mask_is_zero(uint64_t x) {
    return smx_ct_barrier((smx_ct_barrier(x | ((uint64_t)0 - x)) >> 63) - 1);
}

/* All ones if bit is 1, zero if it is 0. */
static inline uint64_t smx_mask_from_bit(uint64_t bit) {
    return smx_ct_barrier((uint64_t)0 - smx_ct_barrier(bit));
}

/* All ones if the top bit of the 32-bit value v is set, otherwise zero. */
static inline uint32_t smx_mask_from_sign32(uint32_t v) {
    return (uint32_t)smx_ct_barrier((uint32_t)0 - ((uint32_t)smx_ct_barrier(v) >> 31));
}

/* Schoolbook 256x256 -> 512. r must not alias a or b. */
static inline void smx_mul_4x4(uint64_t r[8], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t c;
    r[0] = smx_mac(a[0], b[0], 0, 0, &c);
    r[1] = smx_mac(a[0], b[1], 0, c, &c);
    r[2] = smx_mac(a[0], b[2], 0, c, &c);
    r[3] = smx_mac(a[0], b[3], 0, c, &c);
    r[4] = c;
    r[1] = smx_mac(a[1], b[0], r[1], 0, &c);
    r[2] = smx_mac(a[1], b[1], r[2], c, &c);
    r[3] = smx_mac(a[1], b[2], r[3], c, &c);
    r[4] = smx_mac(a[1], b[3], r[4], c, &c);
    r[5] = c;
    r[2] = smx_mac(a[2], b[0], r[2], 0, &c);
    r[3] = smx_mac(a[2], b[1], r[3], c, &c);
    r[4] = smx_mac(a[2], b[2], r[4], c, &c);
    r[5] = smx_mac(a[2], b[3], r[5], c, &c);
    r[6] = c;
    r[3] = smx_mac(a[3], b[0], r[3], 0, &c);
    r[4] = smx_mac(a[3], b[1], r[4], c, &c);
    r[5] = smx_mac(a[3], b[2], r[5], c, &c);
    r[6] = smx_mac(a[3], b[3], r[6], c, &c);
    r[7] = c;
}

/* Dedicated squaring: 6 cross products doubled plus 4 squares. r must not alias a. */
static inline void smx_sqr_4(uint64_t r[8], const uint64_t a[4]) {
    uint64_t c, t1, t2, t3, t4, t5, t6, t7;
    uint64_t h0, h1, h2, h3, l0, l1, l2, l3;

    t1 = smx_mac(a[0], a[1], 0, 0, &c);
    t2 = smx_mac(a[0], a[2], 0, c, &c);
    t3 = smx_mac(a[0], a[3], 0, c, &c);
    t4 = c;
    t3 = smx_mac(a[1], a[2], t3, 0, &c);
    t4 = smx_mac(a[1], a[3], t4, c, &c);
    t5 = c;
    t5 = smx_mac(a[2], a[3], t5, 0, &c);
    t6 = c;

    t7 = t6 >> 63;
    t6 = (t6 << 1) | (t5 >> 63);
    t5 = (t5 << 1) | (t4 >> 63);
    t4 = (t4 << 1) | (t3 >> 63);
    t3 = (t3 << 1) | (t2 >> 63);
    t2 = (t2 << 1) | (t1 >> 63);
    t1 = t1 << 1;

    l0 = smx_mac(a[0], a[0], 0, 0, &h0);
    l1 = smx_mac(a[1], a[1], 0, 0, &h1);
    l2 = smx_mac(a[2], a[2], 0, 0, &h2);
    l3 = smx_mac(a[3], a[3], 0, 0, &h3);

    r[0] = l0;
    r[1] = smx_addc(t1, h0, 0, &c);
    r[2] = smx_addc(t2, l1, c, &c);
    r[3] = smx_addc(t3, h1, c, &c);
    r[4] = smx_addc(t4, l2, c, &c);
    r[5] = smx_addc(t5, h2, c, &c);
    r[6] = smx_addc(t6, l3, c, &c);
    r[7] = t7 + h3 + c;
}

/* ---- branch-free BigInt256 operations, for secret operands ---- */

/* r = a + b, minus m if the sum reaches it. */
static inline void smx_mod_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4],
                               const uint64_t m[4]) {
    uint64_t v[4], t[4], c, bo, keep;
    int i;
    v[0] = smx_addc(a[0], b[0], 0, &c);
    v[1] = smx_addc(a[1], b[1], c, &c);
    v[2] = smx_addc(a[2], b[2], c, &c);
    v[3] = smx_addc(a[3], b[3], c, &c);
    t[0] = smx_subb(v[0], m[0], 0, &bo);
    t[1] = smx_subb(v[1], m[1], bo, &bo);
    t[2] = smx_subb(v[2], m[2], bo, &bo);
    t[3] = smx_subb(v[3], m[3], bo, &bo);
    keep = smx_mask_from_bit(bo & (c ^ 1));
    for (i = 0; i < 4; i++) {
        r[i] = t[i] ^ (keep & (t[i] ^ v[i]));
    }
}

/* r = a - b, plus m if that went negative. */
static inline void smx_mod_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4],
                               const uint64_t m[4]) {
    uint64_t v[4], c, mask;
    v[0] = smx_subb(a[0], b[0], 0, &c);
    v[1] = smx_subb(a[1], b[1], c, &c);
    v[2] = smx_subb(a[2], b[2], c, &c);
    v[3] = smx_subb(a[3], b[3], c, &c);
    mask = smx_mask_from_bit(c);
    r[0] = smx_addc(v[0], m[0] & mask, 0, &c);
    r[1] = smx_addc(v[1], m[1] & mask, c, &c);
    r[2] = smx_addc(v[2], m[2] & mask, c, &c);
    r[3] = smx_addc(v[3], m[3] & mask, c, &c);
}

/* -1, 0 or 1. */
static inline int smx_compare(const uint64_t a[4], const uint64_t b[4]) {
    uint64_t lt = 0, gt = 0;
    int i;
    for (i = 0; i < 4; i++) {
        (void)smx_subb(a[i], b[i], lt, &lt);
        (void)smx_subb(b[i], a[i], gt, &gt);
    }
    return (int)gt - (int)lt;
}

/* ---- secret hygiene ---- */

/* Best-effort erase of a temporary secret; the barrier keeps the compiler from dropping it. */
static inline void smx_wipe(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n-- > 0) {
        *v++ = 0;
    }
#if defined(__GNUC__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

/* ---- byte order ---- */

static inline uint32_t smx_load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void smx_store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline uint64_t smx_load_be64(const uint8_t *p) {
    return ((uint64_t)smx_load_be32(p) << 32) | smx_load_be32(p + 4);
}

static inline void smx_store_be64(uint8_t *p, uint64_t v) {
    smx_store_be32(p, (uint32_t)(v >> 32));
    smx_store_be32(p + 4, (uint32_t)v);
}

/* ---- hex (bigint256.c); branch-free so secret data can pass through ---- */

/* Writes 2 * len characters and no terminator. `alpha` is 'a' or 'A'. */
void smx_hex_encode(const uint8_t *data, size_t len, char *out, char alpha);

/*
 * Decodes exactly 2 * len characters. Returns 1 if they were all hex digits, otherwise 0.
 * It reads everything either way, so the time does not depend on where a bad digit is.
 */
int smx_hex_decode(const char *hex, size_t len, uint8_t *out);

/*
 * The same, accepting only lowercase, which is what this library emits. Signatures and
 * ciphertexts must have one spelling, or a replay cache keyed on the string can be bypassed.
 */
int smx_hex_decode_lower(const char *hex, size_t len, uint8_t *out);

/* ---- SM3 internals (sm3.c), for hashing that never needs hash_hex ---- */

/* Runs the compression function over n consecutive 64-byte blocks. */
void smx_sm3_compress(uint32_t v[8], const uint8_t *blocks, size_t n);

/* Same as sm3_finish, but only fills out[32]; the context is reset for reuse. */
/* The SM2 code never feeds it enough data to reach the 2^61-byte limit. */
void smx_sm3_finish_bytes(SM3 *ctx, uint8_t out[32]);

#endif /* SMX_INTERNAL_H */
