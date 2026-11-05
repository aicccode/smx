/*
 * Security behaviour: the shared vectors in testvectors/security-vectors.json, generated
 * independently of this library, plus the limits and refusals of each entry point.
 *
 * Includes sm4.c itself to reach the S-box internals, so link without sm4.o.
 * The vector path can be given as argv[1]; the 1 GiB SM3 vector takes a few seconds.
 */
#include "sm4.c"
#include "sm2_fp.h"
#include <stdio.h>

static int passed = 0, failed = 0;

#define CHECK(name, cond)                                                                          \
    do {                                                                                           \
        if (cond) {                                                                                \
            passed++;                                                                              \
        } else {                                                                                   \
            failed++;                                                                              \
            printf("  FAIL line %d: %s\n", __LINE__, name);                                        \
        }                                                                                          \
    } while (0)

/* ---- a minimal JSON reader, enough for the vector file ---- */

static char *json_text;

/* Decodes the string at p (just past the opening quote) into a malloc'd C string. */
static char *json_read_string(const char **pp) {
    const char *p = *pp;
    char *out = (char *)malloc(strlen(p) + 1);
    size_t n = 0;
    while (*p != '"') {
        if (*p == '\\') {
            p++;
            if (*p == 'u') {
                unsigned cp = 0;
                int i;
                for (i = 1; i <= 4; i++) {
                    char c = p[i];
                    cp = cp * 16 + (unsigned)(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
                }
                p += 4;
                if (cp < 0x80) {
                    out[n++] = (char)cp;
                } else if (cp < 0x800) {
                    out[n++] = (char)(0xC0 | (cp >> 6));
                    out[n++] = (char)(0x80 | (cp & 63));
                } else {
                    out[n++] = (char)(0xE0 | (cp >> 12));
                    out[n++] = (char)(0x80 | ((cp >> 6) & 63));
                    out[n++] = (char)(0x80 | (cp & 63));
                }
            } else {
                out[n++] = *p;
            }
            p++;
        } else {
            out[n++] = *p++;
        }
    }
    out[n] = '\0';
    *pp = p + 1;
    return out;
}

/* Finds `"key":` after p; returns the position just after the colon and spaces. */
static const char *json_find(const char *p, const char *key) {
    char pattern[128];
    const char *q;
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    q = strstr(p, pattern);
    if (q == NULL) {
        printf("vector file is missing %s\n", key);
        exit(2);
    }
    q += strlen(pattern);
    while (*q == ' ' || *q == '\n') {
        q++;
    }
    return q;
}

static char *json_string_after(const char *section, const char *key) {
    const char *q = json_find(section, key);
    q++; /* the opening quote */
    return json_read_string(&q);
}

/* The string `key` inside the object starting at obj, which ends at the next '}'. */
static char *json_object_string(const char *obj, const char *key) {
    return json_string_after(obj, key);
}

/* Calls fn for each object in the array named key in section. */
typedef void (*ObjectFn)(const char *obj);
static int for_each_object(const char *section, const char *key, ObjectFn fn) {
    const char *p = json_find(section, key);
    int count = 0;
    /* strings in these arrays never contain '{', '}' or ']' */
    p++; /* '[' */
    for (;;) {
        while (*p == ' ' || *p == '\n' || *p == ',') {
            p++;
        }
        if (*p == ']') {
            return count;
        }
        fn(p);
        count++;
        p = strchr(p, '}') + 1;
    }
}

/* Reads an array of integers. */
static int json_int_array(const char *section, const char *key, int *out, int max) {
    const char *p = json_find(section, key);
    int n = 0;
    p++;
    while (*p != ']' && n < max) {
        char *end;
        long v = strtol(p, &end, 10);
        if (end == p) {
            p++;
            continue;
        }
        out[n++] = (int)v;
        p = end;
    }
    return n;
}

/* ---- shared vectors: SM2 ---- */

static char *v_pri, *v_pub, *v_uid, *v_msg, *v_plain, *v_cipher, *v_r, *v_s;
static const char *sm2_section;

static void signature_of(char *out, size_t out_size, const char *r, const char *s) {
    snprintf(out, out_size, "%sh%s", r, s);
}

static void check_invalid_public_key(const char *obj) {
    char *name = json_object_string(obj, "name");
    char *value = json_object_string(obj, "value");
    char sig[140];
    ECPoint p = ec_point_from_hex_encoded(value);
    char *c;
    signature_of(sig, sizeof(sig), v_r, v_s);

    CHECK(name, p.infinity);
    CHECK(name, !ec_point_is_on_curve(&p));
    c = sm2_encrypt(v_plain, value);
    CHECK(name, c == NULL);
    free(c);
    CHECK(name, !sm2_verify(v_uid, sig, v_msg, value));
    free(name);
    free(value);
}

static void check_invalid_private_key(const char *obj) {
    char *name = json_object_string(obj, "name");
    char *value = json_object_string(obj, "value");
    char *sig = sm2_sign(v_uid, v_msg, value);
    char *plain = sm2_decrypt(v_cipher, value);
    CHECK(name, sig == NULL);
    CHECK(name, plain == NULL);
    free(sig);
    free(plain);
    if (strlen(value) == 64) {
        BigInt256 d = bigint256_from_hex(value);
        ECPoint p = sm2_get_public_key(&d);
        CHECK(name, p.infinity);
    }
    free(name);
    free(value);
}

static void check_invalid_signature(const char *obj) {
    char *name = json_object_string(obj, "name");
    char *r = json_object_string(obj, "r");
    char *s = json_object_string(obj, "s");
    char sig[300];
    signature_of(sig, sizeof(sig), r, s);
    CHECK(name, !sm2_verify(v_uid, sig, v_msg, v_pub));
    free(name);
    free(r);
    free(s);
}

static void check_invalid_ciphertext(const char *obj) {
    char *name = json_object_string(obj, "name");
    char *value = json_object_string(obj, "value");
    char *plain = sm2_decrypt(value, v_pri);
    CHECK(name, plain == NULL);
    free(plain);
    free(name);
    free(value);
}

static void test_shared_sm2(void) {
    char sig[140];
    char *plain, *c, *s;
    char *max_key = json_string_after(sm2_section, "n_minus_2_is_max_valid_private_key");
    int n;

    v_pri = json_string_after(sm2_section, "private_key");
    v_pub = json_string_after(sm2_section, "public_key");
    v_uid = json_string_after(sm2_section, "user_id");
    v_msg = json_string_after(sm2_section, "message");
    v_r = json_string_after(sm2_section, "r");
    v_s = json_string_after(sm2_section, "s");
    v_plain = json_string_after(sm2_section, "plaintext");
    v_cipher = json_string_after(sm2_section, "ciphertext");

    {
        BigInt256 d = bigint256_from_hex(v_pri);
        ECPoint p = sm2_get_public_key(&d);
        char hex[131];
        ec_point_to_hex_encoded(&p, hex);
        CHECK("shared public key", strcmp(hex, v_pub) == 0);
    }
    signature_of(sig, sizeof(sig), v_r, v_s);
    CHECK("shared signature verifies", sm2_verify(v_uid, sig, v_msg, v_pub));
    plain = sm2_decrypt(v_cipher, v_pri);
    CHECK("shared ciphertext decrypts", plain != NULL && strcmp(plain, v_plain) == 0);
    free(plain);

    /* n - 2 is the largest private key, and it must work end to end */
    s = sm2_sign(v_uid, v_msg, max_key);
    CHECK("n-2 signs", s != NULL);
    {
        BigInt256 d = bigint256_from_hex(max_key);
        ECPoint p = sm2_get_public_key(&d);
        char hex[131];
        CHECK("n-2 has a public key", !p.infinity);
        ec_point_to_hex_encoded(&p, hex);
        if (s != NULL) {
            CHECK("n-2 signature verifies", sm2_verify(v_uid, s, v_msg, hex));
        }
        c = sm2_encrypt(v_plain, hex);
        plain = sm2_decrypt(c, max_key);
        CHECK("n-2 decrypts", plain != NULL && strcmp(plain, v_plain) == 0);
        free(plain);
        free(c);
    }
    free(s);
    free(max_key);

    n = for_each_object(sm2_section, "invalid_public_keys", check_invalid_public_key);
    CHECK("invalid_public_keys present", n == 17);
    n = for_each_object(sm2_section, "invalid_private_keys", check_invalid_private_key);
    CHECK("invalid_private_keys present", n == 9);
    n = for_each_object(sm2_section, "invalid_signatures", check_invalid_signature);
    CHECK("invalid_signatures present", n == 18);
    n = for_each_object(sm2_section, "invalid_ciphertexts", check_invalid_ciphertext);
    CHECK("invalid_ciphertexts present", n == 14);
}

static void test_user_id_limits(void) {
    int max_len = atoi(json_find(sm2_section, "user_id_max_bytes"));
    int bad_len = atoi(json_find(sm2_section, "user_id_first_invalid_bytes"));
    char *id = (char *)malloc((size_t)bad_len + 2);
    char *s;
    memset(id, 'u', (size_t)bad_len + 1);
    CHECK("the limits are 8191 and 8192", max_len == 8191 && bad_len == 8192);

    id[max_len] = '\0';
    s = sm2_sign(id, v_msg, v_pri);
    CHECK("8191-byte ID signs", s != NULL);
    if (s != NULL) {
        char *other;
        CHECK("8191-byte ID verifies", sm2_verify(id, s, v_msg, v_pub));
        /* ENTL must not wrap: IDs of different lengths must not verify */
        id[max_len] = 'u';
        id[bad_len] = '\0';
        CHECK("8192-byte ID fails to verify", !sm2_verify(id, s, v_msg, v_pub));
        other = sm2_sign(id, v_msg, v_pri);
        CHECK("8192-byte ID fails to sign", other == NULL);
        free(other);
        free(s);
    }
    /* a key exchange ID has the same limit */
    {
        BigInt256 d = bigint256_from_hex(v_pri);
        ECPoint p = sm2_get_public_key(&d);
        SM2KeySwapParams r = sm2_get_sb(16, p, p, p, &d, p, &d, id, "b");
        CHECK("8192-byte ID in key exchange", !r.success);
    }
    free(id);
}

/* ---- key exchange ---- */

static void test_key_exchange_rejections(void) {
    BigInt256 da = bigint256_from_hex(v_pri), db, ra, rb, zero = bigint256_zero();
    BigInt256 n = SM2_N, n_minus_1 = SM2_N;
    ECPoint pa, pb, ra_p, rb_p, inf = ec_point_infinity(), off;
    SM2KeySwapParams b, a;
    uint8_t sb[32], sa[32];
    static const int bad_lengths[] = {0, -1, 257, 1 << 20, 0x7FFFFFFF, -0x7FFFFFFF - 1};
    size_t i;

    n_minus_1.limbs[0] -= 1;
    db = bigint256_from_hex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53");
    ra = bigint256_from_hex("03A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563");
    rb = bigint256_from_hex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80");
    pa = sm2_get_public_key(&da);
    pb = sm2_get_public_key(&db);
    ra_p = sm2_get_public_key(&ra);
    rb_p = sm2_get_public_key(&rb);
    off = pa;
    off.y.value.limbs[0] ^= 1;

    b = sm2_get_sb(16, pa, ra_p, pb, &db, rb_p, &rb, "a", "b");
    CHECK("good exchange, B", b.success);
    hex_to_bytes(b.sb, sb, 32);
    a = sm2_get_sa(16, pb, rb_p, pa, &da, ra_p, &ra, "a", "b", sb, 32);
    CHECK("good exchange, A", a.success && strcmp(a.ka, b.kb) == 0);
    hex_to_bytes(a.sa, sa, 32);
    CHECK("good exchange, check Sa", sm2_check_sa(b.v, b.za, b.zb, ra_p, rb_p, sa, 32));

    /* the largest key length */
    b = sm2_get_sb(256, pa, ra_p, pb, &db, rb_p, &rb, "a", "b");
    CHECK("256-byte key", b.success && strlen(b.kb) == 512);

    for (i = 0; i < sizeof(bad_lengths) / sizeof(bad_lengths[0]); i++) {
        b = sm2_get_sb(bad_lengths[i], pa, ra_p, pb, &db, rb_p, &rb, "a", "b");
        CHECK("bad key length, B", !b.success && b.kb[0] == '\0');
        a = sm2_get_sa(bad_lengths[i], pb, rb_p, pa, &da, ra_p, &ra, "a", "b", sb, 32);
        CHECK("bad key length, A", !a.success && a.ka[0] == '\0');
    }

    /* each peer and own point, off curve and at infinity */
    CHECK("pA off curve", !sm2_get_sb(16, off, ra_p, pb, &db, rb_p, &rb, "a", "b").success);
    CHECK("RA off curve", !sm2_get_sb(16, pa, off, pb, &db, rb_p, &rb, "a", "b").success);
    CHECK("pB off curve", !sm2_get_sb(16, pa, ra_p, off, &db, rb_p, &rb, "a", "b").success);
    CHECK("RB off curve", !sm2_get_sb(16, pa, ra_p, pb, &db, off, &rb, "a", "b").success);
    CHECK("pA infinite", !sm2_get_sb(16, inf, ra_p, pb, &db, rb_p, &rb, "a", "b").success);
    CHECK("RA infinite", !sm2_get_sb(16, pa, inf, pb, &db, rb_p, &rb, "a", "b").success);
    CHECK("pB infinite", !sm2_get_sa(16, inf, rb_p, pa, &da, ra_p, &ra, "a", "b", sb, 32).success);
    CHECK("RB infinite", !sm2_get_sa(16, pb, inf, pa, &da, ra_p, &ra, "a", "b", sb, 32).success);
    CHECK("pA off, A", !sm2_get_sa(16, pb, rb_p, off, &da, ra_p, &ra, "a", "b", sb, 32).success);
    CHECK("RA off, A", !sm2_get_sa(16, pb, rb_p, pa, &da, off, &ra, "a", "b", sb, 32).success);

    /* private values */
    CHECK("dB zero", !sm2_get_sb(16, pa, ra_p, pb, &zero, rb_p, &rb, "a", "b").success);
    CHECK("dB n", !sm2_get_sb(16, pa, ra_p, pb, &n, rb_p, &rb, "a", "b").success);
    CHECK("dB n-1", !sm2_get_sb(16, pa, ra_p, pb, &n_minus_1, rb_p, &rb, "a", "b").success);
    CHECK("rb zero", !sm2_get_sb(16, pa, ra_p, pb, &db, rb_p, &zero, "a", "b").success);
    CHECK("dA n", !sm2_get_sa(16, pb, rb_p, pa, &n, ra_p, &ra, "a", "b", sb, 32).success);
    CHECK("ra zero", !sm2_get_sa(16, pb, rb_p, pa, &da, ra_p, &zero, "a", "b", sb, 32).success);
    CHECK("NULL private", !sm2_get_sb(16, pa, ra_p, pb, NULL, rb_p, &rb, "a", "b").success);

    /* Sa and Sb of any other length, empty above all, must not pass */
    for (i = 0; i < 32; i++) {
        CHECK("short Sb", !sm2_get_sa(16, pb, rb_p, pa, &da, ra_p, &ra, "a", "b", sb, i).success);
        CHECK("short Sa", !sm2_check_sa(b.v, b.za, b.zb, ra_p, rb_p, sa, i));
    }
    CHECK("NULL Sb", !sm2_get_sa(16, pb, rb_p, pa, &da, ra_p, &ra, "a", "b", NULL, 32).success);
    CHECK("NULL Sa", !sm2_check_sa(b.v, b.za, b.zb, ra_p, rb_p, NULL, 32));
    CHECK("check_sa bad V", !sm2_check_sa(off, b.za, b.zb, ra_p, rb_p, sa, 32));
}

/* ---- SM3 ---- */

static void hash_zero_mebibytes(int mib, char out[65]) {
    static uint8_t zeros[1 << 20];
    SM3 h;
    int i;
    sm3_init(&h);
    for (i = 0; i < mib; i++) {
        sm3_update(&h, zeros, sizeof(zeros));
    }
    sm3_finish(&h);
    memcpy(out, h.hash_hex, 65);
}

static void to_lower(char *s) {
    for (; *s; s++) {
        if (*s >= 'A' && *s <= 'F') {
            *s = (char)(*s + 32);
        }
    }
}

static void test_shared_sm3(const char *section) {
    char *want512 = json_string_after(section, "zeros_512_mib");
    char *want1024 = json_string_after(section, "zeros_1024_mib");
    char got[65];
    hash_zero_mebibytes(512, got);
    to_lower(got);
    CHECK("SM3 512 MiB of zeros", strcmp(got, want512) == 0);
    hash_zero_mebibytes(1024, got);
    to_lower(got);
    CHECK("SM3 1024 MiB of zeros", strcmp(got, want1024) == 0);
    free(want512);
    free(want1024);
}

static void test_sm3_limits(void) {
    const uint8_t data[4] = {1, 2, 3, 4};
    SM3 h;
    SM3 reference;

    /* one byte below the limit still works */
    sm3_init(&h);
    h.data_bits_len = (((uint64_t)1 << 61) - 2) * 8;
    sm3_update_byte(&h, 0x61);
    sm3_finish(&h);
    CHECK("the last valid byte", strlen(h.hash_hex) == 64);

    sm3_init(&h);
    h.data_bits_len = (((uint64_t)1 << 61) - 1) * 8;
    sm3_update_byte(&h, 0x61);
    sm3_finish(&h);
    CHECK("one byte too many", h.hash_hex[0] == '\0');

    sm3_init(&h);
    h.data_bits_len = (((uint64_t)1 << 61) - 2) * 8;
    sm3_update(&h, data, 4);
    sm3_update(&h, data, 1);
    sm3_finish(&h);
    CHECK("update beyond the limit stays failed", h.hash_hex[0] == '\0');

    /* the failure must clear on the reset that sm3_finish does */
    sm3_update(&h, (const uint8_t *)"abc", 3);
    sm3_finish(&h);
    CHECK("reuse after failure", strcmp(h.hash_hex, "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7"
                                                    "A2297DA02B8F4BA8E0") == 0);

    /* a corrupted or uninitialized position must not index out of bounds */
    sm3_init(&h);
    h.buff_len = 1000;
    sm3_update(&h, data, 4);
    sm3_update_byte(&h, 1);
    sm3_finish(&h);
    CHECK("bad position is refused", h.hash_hex[0] == '\0');
    sm3_init(&h);
    h.buff_len = -5;
    sm3_finish(&h);
    CHECK("negative position is refused", h.hash_hex[0] == '\0');

    /* a NULL input of nonzero length must not produce the digest of nothing */
    sm3_init(&h);
    sm3_update(&h, NULL, 4);
    sm3_finish(&h);
    CHECK("NULL input", h.hash_hex[0] == '\0');
    sm3_init(&h);
    sm3_update(&h, NULL, 0);
    sm3_finish(&h);
    sm3_init(&reference);
    sm3_finish(&reference);
    CHECK("NULL with no length is empty input", strcmp(h.hash_hex, reference.hash_hex) == 0);
}

/* ---- SM4 ---- */

/* The S-box from GB/T 32907, independent of the circuit and of the affine constants. */
static const uint8_t SM4_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};

static uint32_t expected_sbox_word(uint32_t w) {
    return ((uint32_t)SM4_SBOX[w >> 24] << 24) | ((uint32_t)SM4_SBOX[(w >> 16) & 255] << 16) |
           ((uint32_t)SM4_SBOX[(w >> 8) & 255] << 8) | SM4_SBOX[w & 255];
}

static void test_sbox_implementations(void) {
    uint32_t v;
    int ok_circuit = 1, ok_active = 1;
    /* all 256 values in each of the 4 byte positions, and unrelated bytes alongside */
    for (v = 0; v < 256; v++) {
        int shift;
        for (shift = 0; shift < 32; shift += 8) {
            uint32_t w = v << shift;
            uint32_t w2 = w | ((v * 0x01010101u + 0x5A3C9617u) & ~((uint32_t)0xFF << shift));
            if (sm4_sbox_circuit(w) != expected_sbox_word(w) ||
                sm4_sbox_circuit(w2) != expected_sbox_word(w2)) {
                ok_circuit = 0;
            }
            if (sm4_sbox_word(w) != expected_sbox_word(w) ||
                sm4_sbox_word(w2) != expected_sbox_word(w2)) {
                ok_active = 0;
            }
        }
    }
    CHECK("the circuit is the S-box on all 256 inputs", ok_circuit);
    CHECK("the active word S-box is the S-box", ok_active);
}

static void hex_of(const char *hex, uint8_t *out, size_t len) {
    if (hex_to_bytes(hex, out, len) != (int)len) {
        printf("bad vector hex\n");
        exit(2);
    }
}

static SM4 shared_ctx;

static void check_invalid_padding(const char *obj) {
    char *name = json_object_string(obj, "name");
    char *value = json_object_string(obj, "value");
    char *p = sm4_decrypt(&shared_ctx, value);
    size_t n = 99;
    uint8_t *q = sm4_decrypt_bytes(&shared_ctx, value, &n);
    CHECK(name, p == NULL && q == NULL && n == 0);
    free(p);
    free(q);
    free(name);
    free(value);
}

static void test_shared_sm4(const char *section) {
    char *key_hex = json_string_after(section, "key");
    char *iv_hex = json_string_after(section, "iv");
    char *ct = json_string_after(section, "valid_padded_ciphertext");
    char *pt = json_string_after(section, "valid_padded_plaintext");
    char *full = json_string_after(section, "valid_full_padding_block_ciphertext");
    uint8_t key[16], iv[16], buf[64];
    int lengths[16];
    int n, i;
    SM4 ctx;
    char *out;
    size_t got_len;
    uint8_t *got;

    hex_of(key_hex, key, 16);
    hex_of(iv_hex, iv, 16);
    sm4_init(&shared_ctx);
    sm4_set_key(&shared_ctx, key, 16, iv, 16);

    out = sm4_decrypt(&shared_ctx, ct);
    CHECK("shared valid padding", out != NULL && strcmp(out, pt) == 0);
    free(out);
    out = sm4_encrypt(&shared_ctx, pt);
    CHECK("shared encrypt", out != NULL && strcmp(out, ct) == 0);
    free(out);
    got = sm4_decrypt_bytes(&shared_ctx, full, &got_len);
    CHECK("a whole block of padding decrypts to nothing", got != NULL && got_len == 0);
    free(got);

    memset(buf, 7, sizeof(buf));
    n = json_int_array(section, "invalid_key_lengths_bytes", lengths, 16);
    CHECK("invalid_key_lengths present", n == 6);
    for (i = 0; i < n; i++) {
        sm4_set_key(&ctx, buf, (size_t)lengths[i], iv, 16);
        out = sm4_encrypt(&ctx, "x");
        CHECK("key of a bad length", out == NULL);
        free(out);
        CHECK("key of a bad length, decrypt", sm4_decrypt(&ctx, ct) == NULL);
    }
    n = json_int_array(section, "invalid_iv_lengths_bytes", lengths, 16);
    CHECK("invalid_iv_lengths present", n == 5);
    for (i = 0; i < n; i++) {
        sm4_set_key(&ctx, key, 16, buf, (size_t)lengths[i]);
        out = sm4_encrypt(&ctx, "x");
        CHECK("IV of a bad length", out == NULL);
        free(out);
    }
    n = for_each_object(section, "invalid_paddings", check_invalid_padding);
    CHECK("invalid_paddings present", n == 5);
    n = json_int_array(section, "invalid_ciphertext_lengths_bytes", lengths, 16);
    CHECK("invalid_ciphertext_lengths present", n == 5);
    for (i = 0; i < n; i++) {
        char hex[100];
        memset(hex, 'a', sizeof(hex));
        hex[lengths[i] * 2] = '\0';
        CHECK("ciphertext of a bad length", sm4_decrypt(&shared_ctx, hex) == NULL);
    }
    free(key_hex);
    free(iv_hex);
    free(ct);
    free(pt);
    free(full);
}

static void test_sm4_misuse(void) {
    SM4 ctx;
    uint8_t key[16] = {1};
    char *out;
    size_t n;
    uint8_t *p;
    /* a context that never got a key, even one of arbitrary contents */
    memset(&ctx, 0xA5, sizeof(ctx));
    CHECK("garbage context, encrypt", sm4_encrypt(&ctx, "x") == NULL);
    CHECK("garbage context, decrypt", sm4_decrypt(&ctx, "00") == NULL);
    sm4_init(&ctx);
    CHECK("no key set", sm4_encrypt(&ctx, "x") == NULL);

    /* a failed set_key must not leave the previous key usable */
    sm4_set_key(&ctx, key, 16, key, 16);
    out = sm4_encrypt(&ctx, "x");
    CHECK("key set", out != NULL);
    sm4_set_key(&ctx, key, 15, key, 16);
    CHECK("failed set_key clears the key", sm4_decrypt(&ctx, out) == NULL);
    free(out);

    sm4_set_key(&ctx, key, 16, key, 16);
    /* non-hex and 0x prefixes */
    {
        char hex[33];
        memset(hex, '0', 32);
        hex[32] = '\0';
        hex[31] = 'g';
        CHECK("non-hex in ciphertext", sm4_decrypt(&ctx, hex) == NULL);
        hex[31] = '0';
        hex[1] = 'x';
        CHECK("0x in ciphertext", sm4_decrypt(&ctx, hex) == NULL);
    }
    /* binary round trip, with NULs inside */
    {
        uint8_t data[100];
        int i;
        for (i = 0; i < 100; i++) {
            data[i] = (uint8_t)(i * 3);
        }
        out = sm4_encrypt_bytes(&ctx, data, 100);
        p = sm4_decrypt_bytes(&ctx, out, &n);
        CHECK("binary round trip", p != NULL && n == 100 && memcmp(p, data, 100) == 0);
        free(p);
        free(out);
    }
    /* sizes that cannot be allocated fail before anything is read */
    CHECK("impossible size", sm4_encrypt_bytes(&ctx, key, SIZE_MAX - 8) == NULL);
    CHECK("NULL data", sm4_encrypt_bytes(&ctx, NULL, 16) == NULL);
    out = sm4_encrypt_bytes(&ctx, NULL, 0);
    CHECK("NULL with no length is empty input", out != NULL);
    free(out);
}

/* ---- every entry point on NULL and other misuse ---- */

static void test_null_inputs(void) {
    BigInt256 a = bigint256_one(), r = bigint256_zero();
    ECPoint g = ec_point_generator(), inf = ec_point_infinity();
    uint8_t buf[32];
    char hex[131];
    SM3 h;
    SM4 s4;

    sm3_init(NULL);
    sm3_update_byte(NULL, 1);
    sm3_update(NULL, buf, 1);
    sm3_finish(NULL);
    sm4_init(NULL);
    sm4_set_key(NULL, buf, 16, buf, 16);
    sm4_init(&s4);
    sm4_set_key(&s4, NULL, 16, buf, 16);
    sm4_set_key(&s4, buf, 16, NULL, 16);
    CHECK("sm4_encrypt NULL ctx", sm4_encrypt(NULL, "x") == NULL);
    CHECK("sm4_encrypt NULL text", sm4_encrypt(&s4, NULL) == NULL);
    CHECK("sm4_decrypt NULL ctx", sm4_decrypt(NULL, "x") == NULL);
    CHECK("sm4_decrypt NULL text", sm4_decrypt(&s4, NULL) == NULL);

    CHECK("from_hex NULL", bigint256_is_zero((r = bigint256_from_hex(NULL), &r)));
    CHECK("from_be_bytes NULL", bigint256_is_zero((r = bigint256_from_be_bytes(NULL, 32), &r)));
    bigint256_to_be_bytes(NULL, buf);
    bigint256_to_hex(NULL, hex);
    bigint256_to_hex_lower(&a, NULL);
    CHECK("is_zero NULL", !bigint256_is_zero(NULL));
    CHECK("is_one NULL", !bigint256_is_one(NULL));
    CHECK("compare NULL", bigint256_compare(NULL, &a) == 0);
    CHECK("add NULL", bigint256_add(NULL, &a, &a) == 0);
    CHECK("sub NULL", bigint256_sub(&r, NULL, &a) == 0);
    bigint256_mul(NULL, &a, &a);
    bigint256_mod_add(&r, &a, &a, NULL);
    bigint256_mod_sub(&r, NULL, &a, &a);
    bigint256_mod_mul(&r, &a, NULL, &a);
    bigint256_mod_inverse(NULL, &a, &a);
    bigint256_mod_pow(&r, &a, NULL, &a);
    bigint256_sm2_mod_mul_p(&r, NULL, &a);
    bigint256_sm2_mod_square_p(NULL, &a);
    CHECK("get_bit NULL", bigint256_get_bit(NULL, 0) == 0);
    CHECK("get_bit negative", bigint256_get_bit(&a, -1) == 0);
    CHECK("get_bit huge",
          bigint256_get_bit(&a, 256) == 0 && bigint256_get_bit(&a, 2147483647) == 0);
    CHECK("bit_length NULL", bigint256_bit_length(NULL) == 0);
    bigint256_and(&r, NULL, &a);
    CHECK("fp_from_hex NULL", fp_from_hex(NULL).value.limbs[0] == 0);
    CHECK("fp_is_zero NULL", !fp_is_zero(NULL));
    fp_to_be_bytes(NULL, buf);
    CHECK("point from NULL", ec_point_from_hex_encoded(NULL).infinity);
    ec_point_to_hex_encoded(NULL, hex);
    ec_point_to_hex_encoded(&g, NULL);
    CHECK("on_curve NULL", !ec_point_is_on_curve(NULL));
    CHECK("multiply NULL", ec_point_multiply(g, NULL).infinity);
    CHECK("add both infinite", ec_point_add(inf, inf).infinity);

    sm2_gen_keypair(NULL, hex);
    CHECK("public key NULL", sm2_get_public_key(NULL).infinity);
    CHECK("encrypt NULL", sm2_encrypt(NULL, v_pub) == NULL && sm2_encrypt("x", NULL) == NULL);
    CHECK("encrypt empty", sm2_encrypt("", v_pub) == NULL);
    CHECK("decrypt NULL", sm2_decrypt(NULL, v_pri) == NULL && sm2_decrypt(v_cipher, NULL) == NULL);
    CHECK("sign NULL", sm2_sign(NULL, "m", v_pri) == NULL && sm2_sign("i", NULL, v_pri) == NULL &&
                           sm2_sign("i", "m", NULL) == NULL);
    CHECK("verify NULL", !sm2_verify(NULL, "s", "m", v_pub) && !sm2_verify("i", NULL, "m", v_pub) &&
                             !sm2_verify("i", "s", NULL, v_pub) &&
                             !sm2_verify("i", "s", "m", NULL));
    CHECK("sm2_encrypt_bytes impossible size",
          sm2_encrypt_bytes(buf, ((size_t)0xFFFFFFFFu) * 32 + 1, v_pub) == NULL);
    CHECK("sm2_encrypt_bytes huge size", sm2_encrypt_bytes(buf, SIZE_MAX, v_pub) == NULL);
    CHECK("hex_to_bytes NULL",
          hex_to_bytes(NULL, buf, 1) == -1 && hex_to_bytes("00", NULL, 1) == -1);
    bytes_to_hex(NULL, 1, hex);
    bytes_to_hex(buf, 0, NULL);

    /* sm3 with a real context still works after all that */
    sm3_init(&h);
    sm3_finish(&h);
    CHECK("sm3 unaffected", strlen(h.hash_hex) == 64);
}

/* Points built by hand, which bypass parsing, get the same checks as parsed ones. */
static void test_struct_literal_points(void) {
    ECPoint g = ec_point_generator(), good, bad;
    BigInt256 two = {{2, 0, 0, 0}}, exponent, one = bigint256_one();
    uint64_t x;

    /* x + p must fit in 256 bits, so look for a curve point with a small x; p = 3 mod 4 */
    bigint256_add(&exponent, &SM2_P, &one);
    exponent.limbs[0] = (exponent.limbs[0] >> 2) | (exponent.limbs[1] << 62);
    exponent.limbs[1] = (exponent.limbs[1] >> 2) | (exponent.limbs[2] << 62);
    exponent.limbs[2] = (exponent.limbs[2] >> 2) | (exponent.limbs[3] << 62);
    exponent.limbs[3] >>= 2;
    good = g;
    for (x = 1; x < 100; x++) {
        BigInt256 xv = {{x, 0, 0, 0}}, rhs, yv;
        FpElement fx = fp_new(xv), b;
        b.value =
            bigint256_from_hex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
        /* y^2 = x^3 - 3x + b */
        rhs = fp_add(fp_sub(fp_mul(fp_square(fx), fx), fp_triple(fx)), b).value;
        bigint256_mod_pow(&yv, &rhs, &exponent, &SM2_P);
        good.x = fx;
        good.y.value = yv;
        good.infinity = 0;
        if (ec_point_is_on_curve(&good)) {
            break;
        }
    }
    CHECK("found a curve point with a small x", x < 100);
    bad = good;
    CHECK("x + p fits in 256 bits", bigint256_add(&bad.x.value, &good.x.value, &SM2_P) == 0);
    CHECK("x >= p is not on the curve", !ec_point_is_on_curve(&bad));
    CHECK("x >= p does not multiply", ec_point_multiply(bad, &two).infinity);
    CHECK("x >= p does not add", ec_point_add(bad, g).infinity);
    bad = g;
    bad.infinity = 7;
    CHECK("any nonzero flag means infinity", !ec_point_is_on_curve(&bad));
}

/* The SM2 entry points on strings a parser should refuse. */
static void test_strict_encodings(void) {
    char sig[140], buf[300];
    char *c;
    size_t len;

    /* 0x prefixes */
    snprintf(buf, sizeof(buf), "0x%s", v_pub + 2);
    CHECK("0x public key", ec_point_from_hex_encoded(buf).infinity);
    snprintf(buf, sizeof(buf), "0x%s", v_pri + 2);
    CHECK("0x private key", sm2_sign(v_uid, v_msg, buf) == NULL);

    /* a trailing digit was once ignored */
    snprintf(buf, sizeof(buf), "%s0", v_pub);
    CHECK("131-digit public key", ec_point_from_hex_encoded(buf).infinity);

    /* more than one separator, or in the wrong place */
    signature_of(sig, sizeof(sig), v_r, v_s);
    CHECK("good signature", sm2_verify(v_uid, sig, v_msg, v_pub));
    snprintf(buf, sizeof(buf), "%shh%s", v_r, v_s);
    CHECK("two separators", !sm2_verify(v_uid, buf, v_msg, v_pub));
    snprintf(buf, sizeof(buf), "%sh%s", v_r + 2, v_s);
    CHECK("short r", !sm2_verify(v_uid, buf, v_msg, v_pub));
    snprintf(buf, sizeof(buf), "00%sh%s", v_r, v_s);
    CHECK("padded r", !sm2_verify(v_uid, buf, v_msg, v_pub));

    /* decrypt: a 0x anywhere, and a non-hex digit in each part */
    c = sm2_encrypt("strict", v_pub);
    len = strlen(c);
    {
        size_t positions[3];
        size_t i;
        positions[0] = 10;
        positions[1] = 140;
        positions[2] = len - 1;
        for (i = 0; i < 3; i++) {
            char saved = c[positions[i]];
            char *p;
            c[positions[i]] = 'x';
            p = sm2_decrypt(c, v_pri);
            CHECK("non-hex in ciphertext", p == NULL);
            free(p);
            c[positions[i]] = saved;
        }
    }
    free(c);

    /* from_hex: too long, junk */
    {
        BigInt256 r = bigint256_from_hex("xyz");
        CHECK("from_hex junk", bigint256_is_zero(&r));
        memset(buf, '1', 65);
        buf[65] = '\0';
        r = bigint256_from_hex(buf);
        CHECK("from_hex too long", bigint256_is_zero(&r));
        r = bigint256_from_hex("0x1F");
        CHECK("from_hex short value", r.limbs[0] == 0x1F);
    }
    {
        uint8_t wide[40];
        BigInt256 r;
        memset(wide, 0, sizeof(wide));
        wide[39] = 5;
        r = bigint256_from_be_bytes(wide, 40);
        CHECK("from_be_bytes with zero padding", r.limbs[0] == 5);
        wide[0] = 1;
        r = bigint256_from_be_bytes(wide, 40);
        CHECK("from_be_bytes too large", bigint256_is_zero(&r));
    }
}

/* Binary SM2 data must survive, unlike in the C-string functions. */
static void test_sm2_binary(void) {
    uint8_t data[300];
    size_t n = 0;
    uint8_t *p;
    char *c, *s;
    int i;
    for (i = 0; i < 300; i++) {
        data[i] = (uint8_t)i;
    }
    c = sm2_encrypt_bytes(data, 300, v_pub);
    p = sm2_decrypt_bytes(c, v_pri, &n);
    CHECK("binary SM2 round trip", p != NULL && n == 300 && memcmp(p, data, 300) == 0);
    free(p);
    free(c);
    s = sm2_sign_bytes(v_uid, data, 300, v_pri);
    CHECK("binary signature", sm2_verify_bytes(v_uid, s, data, 300, v_pub));
    CHECK("the bytes after a NUL count", !sm2_verify_bytes(v_uid, s, data, 1, v_pub));
    free(s);
}

static void test_rng_and_keys(void) {
    char a[65], ap[131], b[65], bp[131];
    int i;
    sm2_gen_keypair(a, ap);
    sm2_gen_keypair(b, bp);
    CHECK("keys are 64 digits", strlen(a) == 64 && strlen(ap) == 130);
    CHECK("keys differ", strcmp(a, b) != 0);
    /* nonces: two signatures of one message under one key must differ */
    for (i = 0; i < 20; i++) {
        char *s1 = sm2_sign(v_uid, v_msg, v_pri);
        char *s2 = sm2_sign(v_uid, v_msg, v_pri);
        CHECK("nonces differ", strcmp(s1, s2) != 0);
        free(s1);
        free(s2);
    }
}

/* Signatures and ciphertexts have one spelling; keys are case-insensitive. */
static void swap_case(char *s) {
    for (; *s; s++) {
        if ((*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F')) {
            *s = (char)(*s ^ 0x20);
        }
    }
}

static void test_canonical_hex(void) {
    char sig[140], key[131], pri[65];
    char *c, *t, *p;
    size_t len, i;
    SM4 ctx;
    uint8_t k[16] = {1};

    signature_of(sig, sizeof(sig), v_r, v_s);
    CHECK("lowercase signature verifies", sm2_verify(v_uid, sig, v_msg, v_pub));
    swap_case(sig);
    CHECK("uppercase signature is refused", !sm2_verify(v_uid, sig, v_msg, v_pub));
    signature_of(sig, sizeof(sig), v_r, v_s);
    sig[0] = (char)(sig[0] ^ 0x20); /* first digit is a letter */
    CHECK("one uppercase digit in r is refused", !sm2_verify(v_uid, sig, v_msg, v_pub));

    strcpy(key, v_pub);
    swap_case(key);
    signature_of(sig, sizeof(sig), v_r, v_s);
    CHECK("public key may be uppercase", sm2_verify(v_uid, sig, v_msg, key));
    strcpy(pri, v_pri);
    swap_case(pri);

    c = sm2_encrypt(v_plain, v_pub);
    p = sm2_decrypt(c, pri);
    CHECK("private key may be either case", p != NULL && strcmp(p, v_plain) == 0);
    free(p);
    len = strlen(c);
    /* a letter in each part: C1, C3 and C2 */
    t = (char *)malloc(len + 1);
    for (i = 0; i < len; i++) {
        if (c[i] >= 'a' && c[i] <= 'f') {
            strcpy(t, c);
            t[i] = (char)(t[i] ^ 0x20);
            p = sm2_decrypt(t, v_pri);
            CHECK("uppercase in a ciphertext is refused", p == NULL);
            free(p);
        }
    }
    free(t);
    free(c);

    sm4_init(&ctx);
    sm4_set_key(&ctx, k, 16, k, 16);
    c = sm4_encrypt(&ctx, "canonical");
    p = sm4_decrypt(&ctx, c);
    CHECK("lowercase SM4 ciphertext", p != NULL && strcmp(p, "canonical") == 0);
    free(p);
    swap_case(c);
    CHECK("uppercase SM4 ciphertext is refused", sm4_decrypt(&ctx, c) == NULL);
    free(c);
}

static void test_set_key_aliasing(void) {
    SM4 a, b;
    uint8_t key[16] = {9, 9, 9}, iv[16];
    char *c1, *c2;
    memset(iv, 0xAB, sizeof(iv));
    sm4_init(&a);
    sm4_set_key(&a, key, 16, iv, 16);
    sm4_set_key(&a, key, 16, a.iv, 16); /* the context's own IV */
    CHECK("own IV survives set_key", a.iv[0] == 0xAB && a.iv[15] == 0xAB);
    sm4_init(&b);
    sm4_set_key(&b, key, 16, iv, 16);
    c1 = sm4_encrypt(&a, "alias");
    c2 = sm4_encrypt(&b, "alias");
    CHECK("aliased IV encrypts the same", strcmp(c1, c2) == 0);
    free(c1);
    free(c2);
    sm4_set_key(&a, a.iv, 16, a.iv, 16); /* the key too */
    sm4_set_key(&b, iv, 16, iv, 16);
    CHECK("aliased key expands the same", memcmp(a.rk, b.rk, sizeof(a.rk)) == 0);
}

static void test_sm3_state(void) {
    SM3 h;
    char first[65];
    sm3_init(&h);
    CHECK("no digest before finish", h.hash_hex[0] == '\0');
    sm3_update(&h, (const uint8_t *)"abc", 3);
    CHECK("no digest while hashing", h.hash_hex[0] == '\0');
    sm3_finish(&h);
    memcpy(first, h.hash_hex, 65);
    CHECK("digest after finish", strlen(first) == 64);

    sm3_finish(&h);
    CHECK("finish twice keeps the digest", strcmp(h.hash_hex, first) == 0);

    sm3_update(&h, (const uint8_t *)"x", 1);
    CHECK("update removes the stale digest", h.hash_hex[0] == '\0');
    sm3_finish(&h);
    CHECK("the new digest differs", strlen(h.hash_hex) == 64 && strcmp(h.hash_hex, first) != 0);

    sm3_update_byte(&h, 'x');
    CHECK("update_byte removes the stale digest", h.hash_hex[0] == '\0');
    sm3_finish(&h);

    /* a failure stays visible through a second finish */
    sm3_init(&h);
    sm3_update(&h, NULL, 4);
    sm3_finish(&h);
    sm3_finish(&h);
    CHECK("finish twice after failure stays failed", h.hash_hex[0] == '\0');
    sm3_update(&h, (const uint8_t *)"abc", 3);
    sm3_finish(&h);
    CHECK("new data after failure works", strcmp(h.hash_hex, first) == 0);
}

/* The result must match the math, not a formula that holds only for primes. */
static void test_generic_results(void) {
    BigInt256 r, a, m, zero = bigint256_zero(), one = bigint256_one();
    a = bigint256_from_hex("3");
    m = bigint256_from_hex("A");
    bigint256_mod_inverse(&r, &a, &m);
    CHECK("3^-1 mod 10 = 7", r.limbs[0] == 7);
    a = bigint256_from_hex("4");
    bigint256_mod_inverse(&r, &a, &m);
    CHECK("4 has no inverse mod 10", bigint256_is_zero(&r));
    bigint256_mod_pow(&r, &a, &zero, &one);
    CHECK("x^0 mod 1 = 0", bigint256_is_zero(&r));
    bigint256_mod_pow(&r, &a, &zero, &m);
    CHECK("x^0 mod 10 = 1", bigint256_is_one(&r));
    bigint256_mod_inverse(&r, &a, &one);
    CHECK("inverse mod 1 is 0", bigint256_is_zero(&r));
    bigint256_mod_inverse(&r, &a, &zero);
    CHECK("inverse mod 0 is 0", bigint256_is_zero(&r));
    /* an in-place call */
    a = bigint256_from_hex("3");
    bigint256_mod_inverse(&a, &a, &m);
    CHECK("inverse in place", a.limbs[0] == 7);
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "../testvectors/security-vectors.json";
    FILE *f = fopen(path, "rb");
    long size;
    const char *sm3_section, *sm4_section;

    if (f == NULL) {
        printf("cannot open %s\n", path);
        return 2;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    json_text = (char *)malloc((size_t)size + 1);
    if (fread(json_text, 1, (size_t)size, f) != (size_t)size) {
        printf("cannot read %s\n", path);
        return 2;
    }
    json_text[size] = '\0';
    fclose(f);

    sm2_section = json_find(json_text, "sm2");
    sm3_section = json_find(json_text, "sm3");
    sm4_section = json_find(json_text, "sm4");

    printf("shared SM2 vectors\n");
    test_shared_sm2();
    test_user_id_limits();
    printf("key exchange refusals\n");
    test_key_exchange_rejections();
    printf("SM4\n");
    test_sbox_implementations();
    test_shared_sm4(sm4_section);
    test_sm4_misuse();
    printf("misuse and strict encodings\n");
    test_null_inputs();
    test_struct_literal_points();
    test_strict_encodings();
    test_sm2_binary();
    test_rng_and_keys();
    test_canonical_hex();
    test_set_key_aliasing();
    test_sm3_state();
    test_generic_results();
    printf("SM3\n");
    test_sm3_limits();
    test_shared_sm3(sm3_section);

    printf("\n=== security results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
