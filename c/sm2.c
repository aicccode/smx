#include "smx.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ========== SM2 Curve Constants ========== */

const BigInt256 SM2_P = {{
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL
}};

const BigInt256 SM2_N = {{
    0x53BBF40939D54123ULL, 0x7203DF6B21C6052BULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL
}};

static const FpElement SM2_A = {{{
    0xFFFFFFFFFFFFFFFCULL, 0xFFFFFFFF00000000ULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL
}}};

static const FpElement SM2_B = {{{
    0xDDBCBD414D940E93ULL, 0xF39789F515AB8F92ULL,
    0x4D5A9E4BCF6509A7ULL, 0x28E9FA9E9D9F5E34ULL
}}};

static const FpElement SM2_GX = {{{
    0x715A4589334C74C7ULL, 0x8FE30BBFF2660BE1ULL,
    0x5F9904466A39C994ULL, 0x32C4AE2C1F198119ULL
}}};

static const FpElement SM2_GY = {{{
    0x02DF32E52139F0A0ULL, 0xD0A9877CC62A4740ULL,
    0x59BDCEE36B692153ULL, 0xBC3736A2F4F6779CULL
}}};

/* ========== FpElement ========== */

FpElement fp_new(BigInt256 v) {
    if (bigint256_compare(&v, &SM2_P) >= 0) {
        bigint256_mod_sub(&v, &v, &SM2_P, &SM2_P);
    }
    FpElement r;
    r.value = v;
    return r;
}

FpElement fp_from_hex(const char *s) {
    return fp_new(bigint256_from_hex(s));
}

FpElement fp_zero(void) {
    FpElement r;
    r.value = bigint256_zero();
    return r;
}

FpElement fp_one(void) {
    FpElement r;
    r.value = bigint256_one();
    return r;
}

int fp_is_zero(const FpElement *a) {
    return bigint256_is_zero(&a->value);
}


FpElement fp_add(FpElement a, FpElement b) {
    FpElement r;
    bigint256_mod_add(&r.value, &a.value, &b.value, &SM2_P);
    return r;
}

FpElement fp_sub(FpElement a, FpElement b) {
    FpElement r;
    bigint256_mod_sub(&r.value, &a.value, &b.value, &SM2_P);
    return r;
}

FpElement fp_mul(FpElement a, FpElement b) {
    FpElement r;
    bigint256_sm2_mod_mul_p(&r.value, &a.value, &b.value);
    return r;
}

FpElement fp_square(FpElement a) {
    FpElement r;
    bigint256_sm2_mod_square_p(&r.value, &a.value);
    return r;
}

FpElement fp_negate(FpElement a) {
    if (fp_is_zero(&a)) return a;
    FpElement r;
    bigint256_mod_sub(&r.value, &SM2_P, &a.value, &SM2_P);
    return r;
}

FpElement fp_invert(FpElement a) {
    BigInt256 two = {{2, 0, 0, 0}};
    BigInt256 pm2;
    bigint256_sub(&pm2, &SM2_P, &two);
    BigInt256 result = bigint256_one();
    BigInt256 base = a.value;
    int bit_len = bigint256_bit_length(&pm2);
    int i;
    for (i = 0; i < bit_len; i++) {
        if (bigint256_get_bit(&pm2, i)) {
            bigint256_sm2_mod_mul_p(&result, &result, &base);
        }
        bigint256_sm2_mod_square_p(&base, &base);
    }
    FpElement r;
    r.value = result;
    return r;
}

FpElement fp_double(FpElement a) {
    return fp_add(a, a);
}

FpElement fp_triple(FpElement a) {
    return fp_add(fp_double(a), a);
}

int fp_equal(FpElement a, FpElement b) {
    return bigint256_compare(&a.value, &b.value) == 0;
}

void fp_to_be_bytes(const FpElement *a, uint8_t out[32]) {
    bigint256_to_be_bytes(&a->value, out);
}

/* ========== ECPoint (affine) ========== */

ECPoint ec_point_new(FpElement x, FpElement y) {
    ECPoint p;
    p.x = x; p.y = y; p.infinity = 0;
    return p;
}

ECPoint ec_point_infinity(void) {
    ECPoint p;
    p.x = fp_zero(); p.y = fp_zero(); p.infinity = 1;
    return p;
}

ECPoint ec_point_generator(void) {
    return ec_point_new(SM2_GX, SM2_GY);
}

ECPoint ec_point_from_hex_encoded(const char *hex) {
    size_t hex_len = strlen(hex);
    if (hex_len < 2) return ec_point_infinity();
    size_t byte_len = hex_len / 2;
    uint8_t *data = (uint8_t *)malloc(byte_len);
    hex_to_bytes(hex, data, byte_len);

    ECPoint p;
    if (byte_len == 0) {
        p = ec_point_infinity();
    } else if (data[0] != 0x04 || byte_len != 65) {
        p = ec_point_infinity(); /* unsupported encoding */
    } else {
        FpElement x = fp_new(bigint256_from_be_bytes(data + 1, 32));
        FpElement y = fp_new(bigint256_from_be_bytes(data + 33, 32));
        p = ec_point_new(x, y);
    }
    free(data);
    return p;
}

void ec_point_to_hex_encoded(const ECPoint *p, char out[131]) {
    if (p->infinity) {
        out[0] = '0'; out[1] = '0'; out[2] = '\0';
        return;
    }
    uint8_t encoded[65];
    encoded[0] = 0x04;
    fp_to_be_bytes(&p->x, encoded + 1);
    fp_to_be_bytes(&p->y, encoded + 33);
    bytes_to_hex(encoded, 65, out);
}


int ec_point_is_on_curve(const ECPoint *p) {
    if (p->infinity) return 1;
    /* y^2 = x^3 + a*x + b */
    FpElement lhs = fp_square(p->y);
    FpElement x2_plus_a = fp_add(fp_square(p->x), SM2_A);
    FpElement rhs = fp_add(fp_mul(x2_plus_a, p->x), SM2_B);
    return fp_equal(lhs, rhs);
}

/* ========== Jacobian coordinates ========== */

typedef struct { FpElement x, y, z; } JacobianPoint;

static JacobianPoint jac_infinity(void) {
    JacobianPoint j;
    j.x = fp_one(); j.y = fp_one(); j.z = fp_zero();
    return j;
}

static JacobianPoint jac_from_affine(ECPoint p) {
    if (p.infinity) return jac_infinity();
    JacobianPoint j;
    j.x = p.x; j.y = p.y; j.z = fp_one();
    return j;
}

static ECPoint jac_to_affine(JacobianPoint j) {
    if (fp_is_zero(&j.z)) return ec_point_infinity();
    FpElement zinv = fp_invert(j.z);
    FpElement zinv2 = fp_square(zinv);
    FpElement zinv3 = fp_mul(zinv2, zinv);
    FpElement x = fp_mul(j.x, zinv2);
    FpElement y = fp_mul(j.y, zinv3);
    return ec_point_new(x, y);
}

/* double using a=-3 optimization (dbl-2001-b) */
static JacobianPoint jac_double(JacobianPoint j) {
    if (fp_is_zero(&j.z) || fp_is_zero(&j.y))
        return jac_infinity();

    FpElement delta = fp_square(j.z);
    FpElement gamma = fp_square(j.y);
    FpElement beta  = fp_mul(j.x, gamma);

    /* alpha = 3*(X-delta)*(X+delta) using a=-3 */
    FpElement alpha = fp_triple(fp_mul(fp_sub(j.x, delta), fp_add(j.x, delta)));

    /* X3 = alpha^2 - 8*beta */
    FpElement beta8 = fp_double(fp_double(fp_double(beta)));
    FpElement x3 = fp_sub(fp_square(alpha), beta8);

    /* Z3 = (Y+Z)^2 - gamma - delta */
    FpElement z3 = fp_sub(fp_sub(fp_square(fp_add(j.y, j.z)), gamma), delta);

    /* Y3 = alpha*(4*beta - X3) - 8*gamma^2 */
    FpElement beta4 = fp_double(fp_double(beta));
    FpElement gamma_sq8 = fp_double(fp_double(fp_double(fp_square(gamma))));
    FpElement y3 = fp_sub(fp_mul(alpha, fp_sub(beta4, x3)), gamma_sq8);

    JacobianPoint r;
    r.x = x3; r.y = y3; r.z = z3;
    return r;
}

/* mixed addition: Jacobian + affine */
static JacobianPoint jac_add_affine(JacobianPoint j, ECPoint q) {
    if (q.infinity) return j;
    if (fp_is_zero(&j.z)) return jac_from_affine(q);

    FpElement z1z1 = fp_square(j.z);
    FpElement u2 = fp_mul(q.x, z1z1);
    FpElement s2 = fp_mul(fp_mul(q.y, j.z), z1z1);
    FpElement h  = fp_sub(u2, j.x);
    FpElement rr = fp_sub(s2, j.y);

    if (fp_is_zero(&h)) {
        if (fp_is_zero(&rr)) return jac_double(j);
        return jac_infinity();
    }

    FpElement hh  = fp_square(h);
    FpElement hhh = fp_mul(hh, h);
    FpElement x1hh = fp_mul(j.x, hh);
    FpElement x3 = fp_sub(fp_sub(fp_square(rr), hhh), fp_double(x1hh));
    FpElement y3 = fp_sub(fp_mul(rr, fp_sub(x1hh, x3)), fp_mul(j.y, hhh));
    FpElement z3 = fp_mul(j.z, h);

    JacobianPoint res;
    res.x = x3; res.y = y3; res.z = z3;
    return res;
}

ECPoint ec_point_add(ECPoint p, ECPoint q) {
    if (p.infinity) return q;
    if (q.infinity) return p;
    JacobianPoint jp = jac_from_affine(p);
    JacobianPoint result = jac_add_affine(jp, q);
    return jac_to_affine(result);
}

ECPoint ec_point_multiply(ECPoint p, const BigInt256 *k) {
    if (bigint256_is_zero(k) || p.infinity) return ec_point_infinity();
    if (bigint256_is_one(k)) return p;

    JacobianPoint result = jac_infinity();
    int bit_len = bigint256_bit_length(k);
    int i;
    for (i = bit_len - 1; i >= 0; i--) {
        result = jac_double(result);
        if (bigint256_get_bit(k, i)) {
            result = jac_add_affine(result, p);
        }
    }
    return jac_to_affine(result);
}

/* ========== SM2 internal helpers ========== */

static void random_bytes(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t n = fread(buf, 1, len, f);
        (void)n;
        fclose(f);
    }
}

static BigInt256 random_bigint(void) {
    uint8_t b[32];
    random_bytes(b, 32);
    return bigint256_from_be_bytes(b, 32);
}

static void user_sm3_z(const char *user_id, ECPoint pub, uint8_t z[32]) {
    SM3 sm3;
    sm3_init(&sm3);

    size_t uid_len = strlen(user_id);
    uint16_t entl = (uint16_t)(uid_len * 8);
    sm3_update_byte(&sm3, (uint8_t)(entl >> 8));
    sm3_update_byte(&sm3, (uint8_t)(entl & 0xFF));
    sm3_update(&sm3, (const uint8_t *)user_id, uid_len);

    uint8_t buf[32];
    fp_to_be_bytes(&SM2_A, buf); sm3_update(&sm3, buf, 32);
    fp_to_be_bytes(&SM2_B, buf); sm3_update(&sm3, buf, 32);
    fp_to_be_bytes(&SM2_GX, buf); sm3_update(&sm3, buf, 32);
    fp_to_be_bytes(&SM2_GY, buf); sm3_update(&sm3, buf, 32);
    fp_to_be_bytes(&pub.x, buf); sm3_update(&sm3, buf, 32);
    fp_to_be_bytes(&pub.y, buf); sm3_update(&sm3, buf, 32);

    sm3_finish(&sm3);
    memcpy(z, sm3.hash_bytes, 32);
}

static void sm2_kdf(int keylen, ECPoint p2, uint8_t *out) {
    uint32_t ct = 1;
    int blocks = (keylen + 31) / 32;
    int i;
    for (i = 0; i < blocks; i++) {
        SM3 sm3;
        sm3_init(&sm3);
        uint8_t xb[32], yb[32];
        fp_to_be_bytes(&p2.x, xb);
        fp_to_be_bytes(&p2.y, yb);
        sm3_update(&sm3, xb, 32);
        sm3_update(&sm3, yb, 32);
        uint8_t ct_bytes[4] = {(uint8_t)(ct>>24),(uint8_t)(ct>>16),(uint8_t)(ct>>8),(uint8_t)ct};
        sm3_update(&sm3, ct_bytes, 4);
        sm3_finish(&sm3);

        int start = i * 32;
        int end = (i + 1) * 32;
        if (end > keylen) end = keylen;
        memcpy(out + start, sm3.hash_bytes, (size_t)(end - start));
        ct++;
    }
}

static void sm2_kdf_key_swap(int keylen, ECPoint vu, const uint8_t *za,
                              const uint8_t *zb, uint8_t *out) {
    uint32_t ct = 1;
    int blocks = (keylen + 31) / 32;
    int i;
    for (i = 0; i < blocks; i++) {
        SM3 sm3;
        sm3_init(&sm3);
        uint8_t xb[32], yb[32];
        fp_to_be_bytes(&vu.x, xb);
        fp_to_be_bytes(&vu.y, yb);
        sm3_update(&sm3, xb, 32);
        sm3_update(&sm3, yb, 32);
        sm3_update(&sm3, za, 32);
        sm3_update(&sm3, zb, 32);
        uint8_t ct_bytes[4] = {(uint8_t)(ct>>24),(uint8_t)(ct>>16),(uint8_t)(ct>>8),(uint8_t)ct};
        sm3_update(&sm3, ct_bytes, 4);
        sm3_finish(&sm3);

        int start = i * 32;
        int end = (i + 1) * 32;
        if (end > keylen) end = keylen;
        memcpy(out + start, sm3.hash_bytes, (size_t)(end - start));
        ct++;
    }
}

static BigInt256 calc_x(BigInt256 x) {
    BigInt256 two_pow_w = bigint256_from_hex("80000000000000000000000000000000");
    BigInt256 mask = bigint256_from_hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    BigInt256 x_masked;
    bigint256_and(&x_masked, &x, &mask);
    BigInt256 result;
    bigint256_add(&result, &two_pow_w, &x_masked);
    return result;
}

static BigInt256 calc_t(const BigInt256 *n, const BigInt256 *r,
                         const BigInt256 *d, const BigInt256 *x_) {
    BigInt256 xr;
    bigint256_mod_mul(&xr, x_, r, n);
    BigInt256 result;
    bigint256_mod_add(&result, d, &xr, n);
    return result;
}

static ECPoint calc_point(const BigInt256 *t, const BigInt256 *x_,
                           ECPoint p, ECPoint r) {
    ECPoint xr = ec_point_multiply(r, x_);
    ECPoint sum = ec_point_add(p, xr);
    return ec_point_multiply(sum, t);
}

static void create_s(uint8_t tag, ECPoint vu, const uint8_t *za, const uint8_t *zb,
                      ECPoint ra, ECPoint rb, uint8_t out[32]) {
    SM3 sm3;
    sm3_init(&sm3);
    uint8_t buf[32];
    fp_to_be_bytes(&vu.x, buf); sm3_update(&sm3, buf, 32);
    sm3_update(&sm3, za, 32);
    sm3_update(&sm3, zb, 32);
    fp_to_be_bytes(&ra.x, buf); sm3_update(&sm3, buf, 32);
    fp_to_be_bytes(&ra.y, buf); sm3_update(&sm3, buf, 32);
    fp_to_be_bytes(&rb.x, buf); sm3_update(&sm3, buf, 32);
    fp_to_be_bytes(&rb.y, buf); sm3_update(&sm3, buf, 32);
    sm3_finish(&sm3);
    uint8_t h1[32];
    memcpy(h1, sm3.hash_bytes, 32);

    SM3 hash;
    sm3_init(&hash);
    sm3_update_byte(&hash, tag);
    fp_to_be_bytes(&vu.y, buf); sm3_update(&hash, buf, 32);
    sm3_update(&hash, h1, 32);
    sm3_finish(&hash);
    memcpy(out, hash.hash_bytes, 32);
}

static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

/* ========== SM2 Public API ========== */

ECPoint sm2_get_public_key(const BigInt256 *private_key) {
    return ec_point_multiply(ec_point_generator(), private_key);
}

void sm2_gen_keypair(char pri_hex[65], char pub_hex[131]) {
    for (;;) {
        BigInt256 priv = random_bigint();
        if (bigint256_is_zero(&priv) || bigint256_compare(&priv, &SM2_N) >= 0)
            continue;
        ECPoint pub = sm2_get_public_key(&priv);

        char ph[65], pubh[131];
        bigint256_to_hex(&priv, ph);
        ec_point_to_hex_encoded(&pub, pubh);
        if (strlen(ph) == 64 && strlen(pubh) == 130) {
            memcpy(pri_hex, ph, 65);
            memcpy(pub_hex, pubh, 131);
            return;
        }
    }
}

char *sm2_encrypt(const char *plaintext, const char *public_key_hex) {
    size_t msg_len = strlen(plaintext);
    if (msg_len == 0) return NULL;

    ECPoint pub = ec_point_from_hex_encoded(public_key_hex);
    if (!ec_point_is_on_curve(&pub)) return NULL;

    for (;;) {
        BigInt256 k = random_bigint();
        if (bigint256_is_zero(&k) || bigint256_compare(&k, &SM2_N) >= 0) continue;

        ECPoint c1 = ec_point_multiply(ec_point_generator(), &k);
        ECPoint p2 = ec_point_multiply(pub, &k);
        if (p2.infinity) continue;

        uint8_t *key = (uint8_t *)malloc(msg_len);
        sm2_kdf((int)msg_len, p2, key);

        int all_zero = 1;
        size_t i;
        for (i = 0; i < msg_len; i++) {
            if (key[i] != 0) { all_zero = 0; break; }
        }
        if (all_zero) { free(key); continue; }

        uint8_t *c2 = (uint8_t *)malloc(msg_len);
        for (i = 0; i < msg_len; i++) {
            c2[i] = ((uint8_t)plaintext[i]) ^ key[i];
        }
        free(key);

        /* C3 = SM3(x2 || M || y2) */
        SM3 sm3;
        sm3_init(&sm3);
        uint8_t buf32[32];
        fp_to_be_bytes(&p2.x, buf32); sm3_update(&sm3, buf32, 32);
        sm3_update(&sm3, (const uint8_t *)plaintext, msg_len);
        fp_to_be_bytes(&p2.y, buf32); sm3_update(&sm3, buf32, 32);
        sm3_finish(&sm3);

        /* result = C1_hex || C3_hex || C2_hex */
        char c1_hex[131];
        ec_point_to_hex_encoded(&c1, c1_hex);

        char c3_hex[65];
        bytes_to_hex(sm3.hash_bytes, 32, c3_hex);

        char *c2_hex = (char *)malloc(msg_len * 2 + 1);
        bytes_to_hex(c2, msg_len, c2_hex);
        free(c2);

        size_t total_len = strlen(c1_hex) + strlen(c3_hex) + strlen(c2_hex);
        char *result = (char *)malloc(total_len + 1);
        strcpy(result, c1_hex);
        strcat(result, c3_hex);
        strcat(result, c2_hex);
        free(c2_hex);
        return result;
    }
}

char *sm2_decrypt(const char *ciphertext_hex, const char *private_key_hex) {
    size_t ct_len = strlen(ciphertext_hex);
    if (ct_len < 130 + 64) return NULL;

    /* C1: first 130 hex chars (65 bytes: 04 || x || y) */
    char c1_hex[131];
    memcpy(c1_hex, ciphertext_hex, 130);
    c1_hex[130] = '\0';

    /* C3: next 64 hex chars (32 bytes hash) */
    uint8_t c3[32];
    char c3_hex[65];
    memcpy(c3_hex, ciphertext_hex + 130, 64);
    c3_hex[64] = '\0';
    hex_to_bytes(c3_hex, c3, 32);

    /* C2: remaining */
    const char *c2_hex = ciphertext_hex + 194;
    size_t c2_byte_len = strlen(c2_hex) / 2;
    uint8_t *c2 = (uint8_t *)malloc(c2_byte_len);
    hex_to_bytes(c2_hex, c2, c2_byte_len);

    ECPoint c1 = ec_point_from_hex_encoded(c1_hex);
    if (!ec_point_is_on_curve(&c1)) { free(c2); return NULL; }

    BigInt256 d = bigint256_from_hex(private_key_hex);
    ECPoint p2 = ec_point_multiply(c1, &d);
    if (p2.infinity) { free(c2); return NULL; }

    uint8_t *key = (uint8_t *)malloc(c2_byte_len);
    sm2_kdf((int)c2_byte_len, p2, key);

    size_t i;
    for (i = 0; i < c2_byte_len; i++) {
        c2[i] ^= key[i];
    }
    free(key);

    /* verify C3 */
    SM3 sm3;
    sm3_init(&sm3);
    uint8_t buf32[32];
    fp_to_be_bytes(&p2.x, buf32); sm3_update(&sm3, buf32, 32);
    sm3_update(&sm3, c2, c2_byte_len);
    fp_to_be_bytes(&p2.y, buf32); sm3_update(&sm3, buf32, 32);
    sm3_finish(&sm3);

    if (!bytes_equal(sm3.hash_bytes, c3, 32)) {
        free(c2);
        return NULL;
    }

    char *result = (char *)malloc(c2_byte_len + 1);
    memcpy(result, c2, c2_byte_len);
    result[c2_byte_len] = '\0';
    free(c2);
    return result;
}

char *sm2_sign(const char *user_id, const char *message, const char *private_key_hex) {
    BigInt256 d = bigint256_from_hex(private_key_hex);
    ECPoint pub = sm2_get_public_key(&d);

    uint8_t z[32];
    user_sm3_z(user_id, pub, z);

    SM3 sm3;
    sm3_init(&sm3);
    sm3_update(&sm3, z, 32);
    sm3_update(&sm3, (const uint8_t *)message, strlen(message));
    sm3_finish(&sm3);
    BigInt256 e = bigint256_from_be_bytes(sm3.hash_bytes, 32);

    for (;;) {
        BigInt256 k = random_bigint();
        if (bigint256_is_zero(&k) || bigint256_compare(&k, &SM2_N) >= 0) continue;

        ECPoint kp = ec_point_multiply(ec_point_generator(), &k);
        BigInt256 x1 = kp.x.value;

        BigInt256 r;
        bigint256_mod_add(&r, &e, &x1, &SM2_N);
        if (bigint256_is_zero(&r)) continue;

        BigInt256 rk;
        uint64_t carry = bigint256_add(&rk, &r, &k);
        if (carry == 0 && bigint256_compare(&rk, &SM2_N) == 0) continue;

        BigInt256 one = bigint256_one();
        BigInt256 d_plus_1;
        bigint256_add(&d_plus_1, &d, &one);
        BigInt256 d_plus_1_inv;
        bigint256_mod_inverse(&d_plus_1_inv, &d_plus_1, &SM2_N);

        BigInt256 rd;
        bigint256_mod_mul(&rd, &r, &d, &SM2_N);
        BigInt256 k_minus_rd;
        bigint256_mod_sub(&k_minus_rd, &k, &rd, &SM2_N);
        BigInt256 s;
        bigint256_mod_mul(&s, &k_minus_rd, &d_plus_1_inv, &SM2_N);

        if (bigint256_is_zero(&s)) continue;

        char r_hex[65], s_hex[65];
        bigint256_to_hex_lower(&r, r_hex);
        bigint256_to_hex_lower(&s, s_hex);
        if (strlen(r_hex) == 64 && strlen(s_hex) == 64) {
            /* format: r_hex + "h" + s_hex */
            char *sig = (char *)malloc(64 + 1 + 64 + 1);
            memcpy(sig, r_hex, 64);
            sig[64] = 'h';
            memcpy(sig + 65, s_hex, 64);
            sig[129] = '\0';
            return sig;
        }
    }
}

int sm2_verify(const char *user_id, const char *signature,
                const char *message, const char *public_key_hex) {
    /* split signature on 'h' */
    const char *h_pos = strchr(signature, 'h');
    if (!h_pos) return 0;

    size_t r_len = (size_t)(h_pos - signature);
    char r_str[65], s_str[65];
    if (r_len > 64) return 0;
    memcpy(r_str, signature, r_len);
    r_str[r_len] = '\0';
    size_t s_len = strlen(h_pos + 1);
    if (s_len > 64) return 0;
    memcpy(s_str, h_pos + 1, s_len);
    s_str[s_len] = '\0';

    BigInt256 r = bigint256_from_hex(r_str);
    BigInt256 s = bigint256_from_hex(s_str);

    if (bigint256_is_zero(&r) || bigint256_compare(&r, &SM2_N) >= 0) return 0;
    if (bigint256_is_zero(&s) || bigint256_compare(&s, &SM2_N) >= 0) return 0;

    ECPoint pub = ec_point_from_hex_encoded(public_key_hex);
    if (!ec_point_is_on_curve(&pub)) return 0;

    uint8_t z[32];
    user_sm3_z(user_id, pub, z);

    SM3 sm3;
    sm3_init(&sm3);
    sm3_update(&sm3, z, 32);
    sm3_update(&sm3, (const uint8_t *)message, strlen(message));
    sm3_finish(&sm3);
    BigInt256 e = bigint256_from_be_bytes(sm3.hash_bytes, 32);

    BigInt256 t;
    bigint256_mod_add(&t, &r, &s, &SM2_N);
    if (bigint256_is_zero(&t)) return 0;

    ECPoint sg = ec_point_multiply(ec_point_generator(), &s);
    ECPoint tpa = ec_point_multiply(pub, &t);
    ECPoint point = ec_point_add(sg, tpa);

    if (point.infinity) return 0;

    BigInt256 px = point.x.value;
    BigInt256 computed_r;
    bigint256_mod_add(&computed_r, &e, &px, &SM2_N);
    return bigint256_compare(&r, &computed_r) == 0;
}

/* ========== SM2 Key Exchange ========== */

SM2KeySwapParams sm2_get_sb(int byte_len, ECPoint pA, ECPoint rA, ECPoint pB,
    const BigInt256 *dB, ECPoint rB, const BigInt256 *rb, const char *idA, const char *idB) {

    SM2KeySwapParams result;
    memset(&result, 0, sizeof(result));

    BigInt256 x2_ = calc_x(rB.x.value);
    BigInt256 tb = calc_t(&SM2_N, rb, dB, &x2_);

    if (!ec_point_is_on_curve(&rA)) {
        strcpy(result.message, "RA point is not on curve");
        return result;
    }

    BigInt256 x1_ = calc_x(rA.x.value);
    ECPoint v = calc_point(&tb, &x1_, pA, rA);
    if (v.infinity) {
        strcpy(result.message, "V is point at infinity");
        return result;
    }

    user_sm3_z(idA, pA, result.za);
    user_sm3_z(idB, pB, result.zb);

    uint8_t *kb = (uint8_t *)malloc((size_t)byte_len);
    sm2_kdf_key_swap(byte_len, v, result.za, result.zb, kb);

    uint8_t sb[32];
    create_s(0x02, v, result.za, result.zb, rA, rB, sb);

    bytes_to_hex(sb, 32, result.sb);
    bytes_to_hex(kb, (size_t)byte_len, result.kb);
    free(kb);

    result.v = v;
    result.success = 1;
    return result;
}

SM2KeySwapParams sm2_get_sa(int byte_len, ECPoint pB, ECPoint rB, ECPoint pA,
    const BigInt256 *dA, ECPoint rA, const BigInt256 *ra, const char *idA, const char *idB,
    const uint8_t *sb, size_t sb_len) {

    SM2KeySwapParams result;
    memset(&result, 0, sizeof(result));

    BigInt256 x1_ = calc_x(rA.x.value);
    BigInt256 ta = calc_t(&SM2_N, ra, dA, &x1_);

    if (!ec_point_is_on_curve(&rB)) {
        strcpy(result.message, "RB point is not on curve");
        return result;
    }

    BigInt256 x2_ = calc_x(rB.x.value);
    ECPoint u = calc_point(&ta, &x2_, pB, rB);
    if (u.infinity) {
        strcpy(result.message, "U is point at infinity");
        return result;
    }

    uint8_t za[32], zb[32];
    user_sm3_z(idA, pA, za);
    user_sm3_z(idB, pB, zb);

    uint8_t *ka = (uint8_t *)malloc((size_t)byte_len);
    sm2_kdf_key_swap(byte_len, u, za, zb, ka);

    uint8_t s1[32];
    create_s(0x02, u, za, zb, rA, rB, s1);

    if (!bytes_equal(s1, sb, sb_len < 32 ? sb_len : 32)) {
        free(ka);
        strcpy(result.message, "B's verification value does not match");
        return result;
    }

    uint8_t sa[32];
    create_s(0x03, u, za, zb, rA, rB, sa);

    bytes_to_hex(sa, 32, result.sa);
    bytes_to_hex(ka, (size_t)byte_len, result.ka);
    free(ka);

    result.success = 1;
    return result;
}

int sm2_check_sa(ECPoint v, const uint8_t *za, const uint8_t *zb,
                  ECPoint rA, ECPoint rB, const uint8_t *sa, size_t sa_len) {
    uint8_t s2[32];
    create_s(0x03, v, za, zb, rA, rB, s2);
    return bytes_equal(s2, sa, sa_len < 32 ? sa_len : 32);
}
