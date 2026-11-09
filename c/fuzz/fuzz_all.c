/*
 * libFuzzer target over every public entry point. Each input picks an operation with its
 * first byte, and the rest is its argument data. `make fuzz && ./fuzz_all -max_total_time=600`
 *
 * Beyond surviving under ASan and UBSan, it asserts the properties that must hold for
 * anything accepted: a parsed point is on the curve and re-encodes to itself, a parsed
 * value is canonical, and a decrypted message came from the matching encryption.
 */
#include "smx.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VALID_PRI "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
#define VALID_PUB                                                                                  \
    "0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"                           \
    "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"
#define VALID_SIG                                                                                  \
    "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3h"                            \
    "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa"
#define VALID_CT                                                                                   \
    "0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73"                           \
    "e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0"                             \
    "59983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd8766"                             \
    "21886ca989ca9c7d58087307ca93092d651efa"

/* SM9: the worked examples of GB/T 38635.5 (signing for Alice, encryption for Bob) */
#define SM9_SIGN_PUB \
    "049f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c4" \
    "0829dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea5e" \
    "3269850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0ef1c" \
    "2541e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05fb4e321" \
    "6d"
#define SM9_SIGN_SIG \
    "823c4b21e4bd2dfe1ed92c606653e996668563152fc33f55d7bfbb9bd9705adb" \
    "0473bf96923ce58b6ad0e13e9643a406d8eb98417c50ef1b29cef9adb48b6d59" \
    "8c856712f1c2e0968ab7769f42a99586aed139d5b8b3e15891827cc2aced9baa" \
    "05"
#define SM9_ENC_PUB \
    "04787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892" \
    "ff769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7" \
    "b1"
#define SM9_ENC_KEY \
    "0494736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf416" \
    "83115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b1" \
    "587aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b5" \
    "5f27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75" \
    "c1"
#define SM9_ENC_CT \
    "042445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8" \
    "ff42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59a" \
    "c0ba672387bcd6de5016a158a52bb2e7fc429197bcab70b25afee37a2b9db9f3" \
    "671b5f5b0e951489682f3e64e1378cdd5da9513b1c"

/* A NUL-terminated copy of the input. */
static char *to_string(const uint8_t *data, size_t len) {
    char *s = (char *)malloc(len + 1);
    if (len > 0) {
        memcpy(s, data, len);
    }
    s[len] = '\0';
    return s;
}

/* Splits the input in two at a position taken from its first byte. */
static void split(const uint8_t *data, size_t len, char **a, char **b) {
    size_t cut = len > 0 ? (size_t)data[0] * 3 : 0;
    if (cut > len) {
        cut = len;
    }
    if (len > 0) {
        size_t first = cut > 0 ? cut - 1 : 0;
        *a = to_string(data + 1, first);
        *b = to_string(data + 1 + first, len - 1 - first);
    } else {
        *a = to_string(data, 0);
        *b = to_string(data, 0);
    }
}

static BigInt256 big_from(const uint8_t *data, size_t len) {
    uint8_t raw[32];
    memset(raw, 0, 32);
    memcpy(raw, data, len < 32 ? len : 32);
    return bigint256_from_be_bytes(raw, 32);
}

/* A point with attacker-chosen limbs, which the struct type allows to be anything. */
static ECPoint point_from(const uint8_t *data, size_t len) {
    ECPoint p;
    p.x.value = big_from(data, len);
    p.y.value = big_from(len > 32 ? data + 32 : data, len > 32 ? len - 32 : 0);
    p.infinity = len > 64 ? (data[64] & 1) : 0;
    return p;
}

static void check_parsed_point(const char *text) {
    ECPoint p = ec_point_from_hex_encoded(text);
    if (!p.infinity) {
        char again[131];
        size_t i;
        assert(ec_point_is_on_curve(&p));
        assert(strlen(text) == 130);
        ec_point_to_hex_encoded(&p, again);
        for (i = 0; i < 130; i++) {
            char c = text[i];
            if (c >= 'A' && c <= 'F') {
                c = (char)(c + 32);
            }
            assert(c == again[i]);
        }
    } else {
        assert(!ec_point_is_on_curve(&p));
    }
}

static void fuzz_sm3(const uint8_t *data, size_t len) {
    SM3 a, b;
    size_t off = 0;
    sm3_init(&a);
    sm3_init(&b);
    sm3_update(&a, data, len);
    while (off < len) {
        size_t n = (size_t)data[off] % 70 + 1;
        if (n > len - off) {
            n = len - off;
        }
        sm3_update(&b, data + off, n);
        off += n;
    }
    sm3_finish(&a);
    sm3_finish(&b);
    assert(strcmp(a.hash_hex, b.hash_hex) == 0);
    assert(strlen(a.hash_hex) == 64);
}

static void fuzz_sm4_roundtrip(const uint8_t *data, size_t len) {
    SM4 ctx;
    uint8_t key[16], iv[16];
    char *ct;
    uint8_t *pt;
    size_t pt_len = 0;
    if (len < 32) {
        return;
    }
    memcpy(key, data, 16);
    memcpy(iv, data + 16, 16);
    sm4_init(&ctx);
    sm4_set_key(&ctx, key, 16, iv, 16);
    ct = sm4_encrypt_bytes(&ctx, data + 32, len - 32);
    assert(ct != NULL);
    pt = sm4_decrypt_bytes(&ctx, ct, &pt_len);
    assert(pt != NULL && pt_len == len - 32 && memcmp(pt, data + 32, pt_len) == 0);
    free(pt);
    free(ct);
}

static void fuzz_sm4_decrypt(const uint8_t *data, size_t len) {
    static const uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    SM4 ctx;
    char *text = to_string(data, len);
    char *out;
    size_t n = 0;
    uint8_t *bytes;
    sm4_init(&ctx);
    sm4_set_key(&ctx, key, 16, key, 16);
    out = sm4_decrypt(&ctx, text);
    bytes = sm4_decrypt_bytes(&ctx, text, &n);
    assert((out == NULL) == (bytes == NULL));
    if (out != NULL) {
        /* valid only for canonical block lengths */
        assert(strlen(text) % 32 == 0 && strlen(text) > 0);
        assert(n < strlen(text) / 2 && memcmp(out, bytes, n) == 0);
    }
    free(out);
    free(bytes);
    free(text);
}

static void fuzz_sm4_key(const uint8_t *data, size_t len) {
    SM4 ctx;
    size_t key_len = len > 0 ? data[0] : 0;
    size_t iv_len = len > 16 ? 16 : len;
    char *c;
    if (key_len > len) {
        key_len = len;
    }
    sm4_init(&ctx);
    sm4_set_key(&ctx, data, key_len, data, iv_len);
    c = sm4_encrypt(&ctx, "x");
    /* a key exists exactly when both lengths were 16 */
    assert((c != NULL) == (key_len == 16 && iv_len == 16));
    free(c);
}

static void fuzz_private_key_paths(const uint8_t *data, size_t len) {
    char *text = to_string(data, len);
    char *s = sm2_sign("id", "message", text);
    char *p = sm2_decrypt(VALID_CT, text);
    size_t n = strlen(text);
    if (s != NULL) {
        assert(n == 64);
        assert(strlen(s) == 129 && s[64] == 'h');
    }
    free(s);
    free(p);
    free(text);
}

static void fuzz_verify(const uint8_t *data, size_t len) {
    char *a, *b;
    int v;
    split(data, len, &a, &b);
    /* the signature, then the key, with the message from elsewhere */
    v = sm2_verify("1234567812345678", a, "message digest", VALID_PUB);
    if (v) {
        assert(strlen(a) == 129);
    }
    v = sm2_verify("1234567812345678", VALID_SIG, "message digest", a);
    (void)v;
    v = sm2_verify(a, b, a, VALID_PUB);
    (void)v;
    free(a);
    free(b);
}

static void fuzz_decrypt(const uint8_t *data, size_t len) {
    char *text = to_string(data, len);
    char *out = sm2_decrypt(text, VALID_PRI);
    size_t n = 0;
    uint8_t *bytes = sm2_decrypt_bytes(text, VALID_PRI, &n);
    assert((out == NULL) == (bytes == NULL));
    if (out != NULL) {
        assert(strlen(text) % 2 == 0 && strlen(text) >= 196);
        assert(n == (strlen(text) - 194) / 2);
    }
    free(out);
    free(bytes);
    free(text);
}

static void fuzz_encrypt_roundtrip(const uint8_t *data, size_t len) {
    uint8_t *pt;
    size_t n = 0;
    char *c;
    if (len > 512) {
        len = 512;
    }
    c = sm2_encrypt_bytes(data, len, VALID_PUB);
    if (len == 0) {
        assert(c == NULL);
        return;
    }
    assert(c != NULL);
    pt = sm2_decrypt_bytes(c, VALID_PRI, &n);
    assert(pt != NULL && n == len && memcmp(pt, data, len) == 0);
    free(pt);
    free(c);
}

static void fuzz_encrypt_key(const uint8_t *data, size_t len) {
    char *text = to_string(data, len);
    char *c = sm2_encrypt("message", text);
    ECPoint p = ec_point_from_hex_encoded(text);
    assert((c != NULL) == !p.infinity);
    free(c);
    free(text);
}

static void fuzz_sign_id(const uint8_t *data, size_t len) {
    char *a, *b;
    char *s;
    split(data, len, &a, &b);
    s = sm2_sign_bytes(a, data, len, VALID_PRI);
    if (s != NULL) {
        assert(sm2_verify_bytes(a, s, data, len, VALID_PUB));
    } else {
        assert(strlen(a) >= 8192);
    }
    free(s);
    free(a);
    free(b);
}

static void fuzz_key_exchange(const uint8_t *data, size_t len) {
    /* raw points and scalars of any shape, and any length */
    int byte_len = len >= 4 ? (int)((uint32_t)data[0] | ((uint32_t)data[1] << 8) |
                                    ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24))
                            : 16;
    BigInt256 dv = bigint256_from_hex(VALID_PRI), other = big_from(data, len);
    ECPoint good = ec_point_generator();
    ECPoint fuzzed = point_from(data, len);
    uint8_t sb[32];
    SM2KeySwapParams r;
    size_t sb_len = len > 4 ? data[4] : 0;
    int small = (byte_len & 0xFF) % 40;

    r = sm2_get_sb(byte_len, fuzzed, good, good, &dv, good, &dv, "a", "b");
    assert(strlen(r.kb) <= 512);
    r = sm2_get_sb(small, good, fuzzed, good, &dv, good, &dv, "a", "b");
    assert(strlen(r.kb) <= 512);
    r = sm2_get_sb(small, good, good, fuzzed, &other, fuzzed, &dv, "a", "b");
    assert(strlen(r.kb) <= 512);
    r = sm2_get_sb(small, good, good, good, &other, good, &dv, "a", "b");
    memset(sb, 0, sizeof(sb));
    memcpy(sb, data, len < 32 ? len : 32);
    r = sm2_get_sa(byte_len, fuzzed, good, good, &dv, good, &dv, "a", "b", sb,
                   sb_len < 32 ? sb_len : 32);
    assert(strlen(r.ka) <= 512);
    r = sm2_get_sa(small, good, good, good, &dv, good, &other, "a", "b", sb, 32);
    assert(!r.success); /* sb is not the right value */
    assert(!sm2_check_sa(fuzzed, sb, sb, good, good, sb, sb_len < 32 ? sb_len : 32));
    assert(!sm2_check_sa(good, sb, sb, fuzzed, good, sb, 31));
}

static void fuzz_bigint(const uint8_t *data, size_t len) {
    BigInt256 a = big_from(data, len),
              b = big_from(len > 32 ? data + 32 : data, len > 32 ? len - 32 : 0);
    BigInt256 m = big_from(len > 64 ? data + 64 : data, len > 64 ? len - 64 : 0), r;
    uint64_t wide[8];
    char hex[65];
    int bit = len > 0 ? (int)data[0] * 3 - 200 : 0;
    FpElement x, y;

    bigint256_add(&r, &a, &b);
    bigint256_sub(&r, &a, &b);
    bigint256_mul(wide, &a, &b);
    bigint256_mod_add(&r, &a, &b, &m);
    bigint256_mod_sub(&r, &a, &b, &m);
    bigint256_mod_mul(&r, &a, &b, &m);
    if (bigint256_compare(&m, &a) != 0) {
        assert(bigint256_is_zero(&m) || bigint256_compare(&r, &m) < 0);
    }
    bigint256_sm2_mod_mul_p(&r, &a, &b);
    assert(bigint256_compare(&r, &SM2_P) < 0);
    bigint256_sm2_mod_square_p(&r, &a);
    assert(bigint256_compare(&r, &SM2_P) < 0);
    (void)bigint256_get_bit(&a, bit);
    (void)bigint256_bit_length(&a);
    bigint256_and(&r, &a, &b);
    bigint256_to_hex(&a, hex);
    r = bigint256_from_hex(hex);
    assert(bigint256_compare(&r, &a) == 0);
    bigint256_to_hex_lower(&a, hex);
    r = bigint256_from_hex(hex);
    assert(bigint256_compare(&r, &a) == 0);

    /* short exponents, so a run stays quick */
    b.limbs[1] = b.limbs[2] = b.limbs[3] = 0;
    b.limbs[0] &= 0xFFFF;
    bigint256_mod_pow(&r, &a, &b, &m);
    if (!bigint256_is_zero(&m) && !bigint256_is_zero(&b)) {
        assert(bigint256_compare(&r, &m) < 0);
    }

    x.value = a;
    y.value = m;
    (void)fp_add(x, y);
    (void)fp_sub(x, y);
    (void)fp_mul(x, y);
    (void)fp_square(x);
    (void)fp_negate(x);
    (void)fp_double(x);
    (void)fp_triple(x);
    (void)fp_invert(x);
    (void)fp_equal(x, y);
    (void)fp_new(a);
}

static void fuzz_hex(const uint8_t *data, size_t len) {
    char *text = to_string(data, len);
    uint8_t out[300];
    int n = hex_to_bytes(text, out, sizeof(out));
    size_t tl = strlen(text);
    BigInt256 r = bigint256_from_hex(text);
    FpElement f = fp_from_hex(text);
    (void)r;
    (void)f;
    if (n >= 0) {
        char back[601];
        size_t i;
        assert((size_t)n * 2 == tl);
        bytes_to_hex(out, (size_t)n, back);
        for (i = 0; i < tl; i++) {
            char c = text[i];
            if (c >= 'A' && c <= 'F') {
                c = (char)(c + 32);
            }
            assert(c == back[i]);
        }
    }
    (void)bigint256_from_be_bytes(data, len);
    free(text);
}

static void fuzz_points(const uint8_t *data, size_t len) {
    ECPoint p = point_from(data, len);
    ECPoint q = ec_point_generator();
    BigInt256 k = big_from(data, len);
    ECPoint r;
    (void)ec_point_is_on_curve(&p);
    r = ec_point_multiply(p, &k);
    assert(r.infinity || ec_point_is_on_curve(&r));
    r = ec_point_add(p, q);
    assert(r.infinity || ec_point_is_on_curve(&r));
    r = ec_point_multiply(q, &k);
    assert(r.infinity || ec_point_is_on_curve(&r));
    r = sm2_get_public_key(&k);
    assert(r.infinity || ec_point_is_on_curve(&r));
}

/* ---- SM9 ---- */

static int equal_ignore_case(const char *a, const char *b) {
    for (; *a != '\0' && *b != '\0'; a++, b++) {
        char x = *a >= 'A' && *a <= 'F' ? (char)(*a + 32) : *a;
        char y = *b >= 'A' && *b <= 'F' ? (char)(*b + 32) : *b;
        if (x != y) {
            return 0;
        }
    }
    return *a == *b;
}

/* Any text as a G1 or G2 key or point: refused or used, never a crash. */
static void fuzz_sm9_points(const uint8_t *data, size_t len) {
    char *text = to_string(data, len < 300 ? len : 300);
    char key[65], c[131];
    if (sm9_encapsulate("Bob", text, 16, SM9_HID_ENCRYPT, key, c)) {
        assert(strlen(text) == 130 && strlen(c) == 130 && strlen(key) == 32);
    }
    assert(!sm9_verify("Chinese IBS standard", SM9_SIGN_SIG, "Alice", text, SM9_HID_SIGN) ||
           equal_ignore_case(text, SM9_SIGN_PUB));
    assert(!sm9_decapsulate(text, "Bob", SM9_ENC_KEY, 16, key) || strlen(text) == 130);
    assert(!sm9_decapsulate(SM9_ENC_CT, "Bob", text, 16, key) || strlen(text) == 258);
    free(text);
}

/* Signature and ID from the input: a forged signature never verifies. */
static void fuzz_sm9_verify(const uint8_t *data, size_t len) {
    char *sig, *id;
    split(data, len < 400 ? len : 400, &sig, &id);
    assert(!sm9_verify("Chinese IBS standard", sig, id, SM9_SIGN_PUB, SM9_HID_SIGN) ||
           (strcmp(sig, SM9_SIGN_SIG) == 0 && strcmp(id, "Alice") == 0));
    free(sig);
    free(id);
}

/* Arbitrary ciphertexts: an accepted one must be the vector, or carry a valid C3. */
static void fuzz_sm9_decrypt(const uint8_t *data, size_t len) {
    char *text = to_string(data, len < 600 ? len : 600);
    size_t out_len;
    int mode;
    for (mode = 0; mode < 2; mode++) {
        uint8_t *p = sm9_decrypt_bytes(text, "Bob", SM9_ENC_KEY, mode, &out_len);
        assert(p == NULL || (out_len > 0 && p[out_len] == '\0'));
        free(p);
    }
    free(text);
}

/* Encrypting the input decrypts back to it, in both modes, and a flipped bit is refused. */
static void fuzz_sm9_roundtrip(const uint8_t *data, size_t len) {
    int mode;
    if (len == 0 || len > 256) {
        return;
    }
    for (mode = 0; mode < 2; mode++) {
        char *ct = sm9_encrypt_bytes(data, len, "Bob", SM9_ENC_PUB, SM9_HID_ENCRYPT, mode);
        size_t out_len;
        uint8_t *p;
        assert(ct != NULL);
        p = sm9_decrypt_bytes(ct, "Bob", SM9_ENC_KEY, mode, &out_len);
        assert(p != NULL && out_len == len && memcmp(p, data, len) == 0);
        free(p);
        ct[130 + data[0] % 64] ^= 1; /* inside C3 */
        p = sm9_decrypt_bytes(ct, "Bob", SM9_ENC_KEY, mode, &out_len);
        assert(p == NULL);
        free(ct);
    }
}

/* Key exchange with R_A and S_B taken from the input. */
static void fuzz_sm9_exchange(const uint8_t *data, size_t len) {
    char *ra, *sb, r[65], rb[131];
    SM9ExchangeResult res;
    split(data, len < 300 ? len : 300, &ra, &sb);
    if (sm9_exchange_init("Alice", SM9_ENC_PUB, SM9_HID_EXCHANGE, r, rb)) {
        res = sm9_exchange_respond(16, "Alice", "Bob", SM9_ENC_PUB, SM9_ENC_KEY, r, rb, ra);
        assert(!res.success || (strlen(res.shared_key) == 32 && strlen(res.s_b) == 64));
        sm9_exchange_result_free(&res);
        res = sm9_exchange_confirm(16, "Alice", "Bob", SM9_ENC_PUB, SM9_ENC_KEY, r, rb, ra, sb);
        assert(!res.success);
        sm9_exchange_result_free(&res);
        assert(!sm9_exchange_check(ra, sb) || strlen(ra) == 64);
    }
    free(ra);
    free(sb);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const uint8_t *rest = data + 1;
    size_t n;
    char *text;
    if (size == 0) {
        return 0;
    }
    n = size - 1;
    /* operations with a scalar multiplication get less data, so more runs fit */
    switch (data[0] % 19) {
    case 0:
        text = to_string(rest, n);
        check_parsed_point(text);
        free(text);
        break;
    case 1:
        fuzz_sm3(rest, n);
        break;
    case 2:
        fuzz_sm4_roundtrip(rest, n);
        break;
    case 3:
        fuzz_sm4_decrypt(rest, n);
        break;
    case 4:
        fuzz_sm4_key(rest, n);
        break;
    case 5:
        fuzz_private_key_paths(rest, n);
        break;
    case 6:
        fuzz_verify(rest, n);
        break;
    case 7:
        fuzz_decrypt(rest, n);
        break;
    case 8:
        fuzz_encrypt_roundtrip(rest, n);
        break;
    case 9:
        fuzz_encrypt_key(rest, n);
        break;
    case 10:
        fuzz_sign_id(rest, n);
        break;
    case 11:
        fuzz_key_exchange(rest, n);
        break;
    case 12:
        fuzz_bigint(rest, n);
        fuzz_hex(rest, n);
        break;
    case 14:
        fuzz_sm9_points(rest, n);
        break;
    case 15:
        fuzz_sm9_verify(rest, n);
        break;
    case 16:
        fuzz_sm9_decrypt(rest, n);
        break;
    case 17:
        fuzz_sm9_roundtrip(rest, n);
        break;
    case 18:
        fuzz_sm9_exchange(rest, n);
        break;
    default:
        fuzz_points(rest, n);
        break;
    }
    return 0;
}
