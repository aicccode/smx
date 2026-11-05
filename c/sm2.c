#include "sm2_ec.h"
#include "sm2_fn.h"
#include "smx_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========== SM2 Curve Constants ========== */

const BigInt256 SM2_P = {
    {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL}};

const BigInt256 SM2_N = {
    {0x53BBF40939D54123ULL, 0x7203DF6B21C6052BULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL}};

static const FpElement SM2_A = {
    {{0xFFFFFFFFFFFFFFFCULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL}}};

static const FpElement SM2_B = {
    {{0xDDBCBD414D940E93ULL, 0xF39789F515AB8F92ULL, 0x4D5A9E4BCF6509A7ULL, 0x28E9FA9E9D9F5E34ULL}}};

/* ========== FpElement ========== */

FpElement fp_new(BigInt256 v) {
    FpElement r;
    fe_reduce_once(r.value.limbs, v.limbs, 0);
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
    fe_add(r.value.limbs, a.value.limbs, b.value.limbs);
    return r;
}

FpElement fp_sub(FpElement a, FpElement b) {
    FpElement r;
    fe_sub(r.value.limbs, a.value.limbs, b.value.limbs);
    return r;
}

FpElement fp_mul(FpElement a, FpElement b) {
    FpElement r;
    fe_mul(r.value.limbs, a.value.limbs, b.value.limbs);
    return r;
}

FpElement fp_square(FpElement a) {
    FpElement r;
    fe_sqr(r.value.limbs, a.value.limbs);
    return r;
}

FpElement fp_negate(FpElement a) {
    FpElement r;
    fe_sub(r.value.limbs, FE_P, a.value.limbs);
    fe_cmov(r.value.limbs, a.value.limbs, fe_is_zero(a.value.limbs));
    return r;
}

FpElement fp_invert(FpElement a) {
    FpElement r;
    fe_inv(r.value.limbs, a.value.limbs);
    return r;
}

FpElement fp_double(FpElement a) {
    return fp_add(a, a);
}

FpElement fp_triple(FpElement a) {
    return fp_add(fp_double(a), a);
}

int fp_equal(FpElement a, FpElement b) {
    return fe_equal(a.value.limbs, b.value.limbs) != 0;
}

void fp_to_be_bytes(const FpElement *a, uint8_t out[32]) {
    bigint256_to_be_bytes(&a->value, out);
}

/* ========== ECPoint (affine) ========== */

ECPoint ec_point_new(FpElement x, FpElement y) {
    ECPoint p;
    p.x = x;
    p.y = y;
    p.infinity = 0;
    return p;
}

ECPoint ec_point_infinity(void) {
    ECPoint p;
    p.x = fp_zero();
    p.y = fp_zero();
    p.infinity = 1;
    return p;
}

ECPoint ec_point_generator(void) {
    ECPoint p;
    fe_copy(p.x.value.limbs, EC_GX);
    fe_copy(p.y.value.limbs, EC_GY);
    p.infinity = 0;
    return p;
}

ECPoint ec_point_from_hex_encoded(const char *hex) {
    size_t hex_len = strlen(hex);
    uint8_t data[65];

    /* anything else is not an uncompressed point; a trailing odd digit is ignored */
    if (hex_len != 130 && hex_len != 131) {
        return ec_point_infinity();
    }
    memset(data, 0, sizeof(data));
    hex_to_bytes(hex, data, sizeof(data));
    if (data[0] != 0x04) {
        return ec_point_infinity();
    }
    return ec_point_new(fp_new(bigint256_from_be_bytes(data + 1, 32)),
                        fp_new(bigint256_from_be_bytes(data + 33, 32)));
}

void ec_point_to_hex_encoded(const ECPoint *p, char out[131]) {
    uint8_t encoded[65];
    if (p->infinity) {
        out[0] = '0';
        out[1] = '0';
        out[2] = '\0';
        return;
    }
    encoded[0] = 0x04;
    fp_to_be_bytes(&p->x, encoded + 1);
    fp_to_be_bytes(&p->y, encoded + 33);
    bytes_to_hex(encoded, 65, out);
}

int ec_point_is_on_curve(const ECPoint *p) {
    Fe lhs, rhs;
    if (p->infinity) {
        return 1;
    }
    /* y^2 = (x^2 + a) * x + b */
    fe_sqr(lhs, p->y.value.limbs);
    fe_sqr(rhs, p->x.value.limbs);
    fe_add(rhs, rhs, SM2_A.value.limbs);
    fe_mul(rhs, rhs, p->x.value.limbs);
    fe_add(rhs, rhs, SM2_B.value.limbs);
    return fe_equal(lhs, rhs) != 0;
}

/* ---- conversions between the public affine type and Jacobian ---- */

static void jac_from_point(Jac *r, const ECPoint *p) {
    if (p->infinity) {
        jac_set_infinity(r);
        return;
    }
    /* points built with ec_point_new may hold unreduced coordinates */
    fe_reduce_once(r->x, p->x.value.limbs, 0);
    fe_reduce_once(r->y, p->y.value.limbs, 0);
    fe_copy(r->z, FE_ONE);
}

/* Converts given the inverse of Z. */
static ECPoint point_from_jac_zinv(const Jac *j, const Fe zinv) {
    ECPoint p;
    Fe zinv2, zinv3;
    fe_sqr(zinv2, zinv);
    fe_mul(zinv3, zinv2, zinv);
    fe_mul(p.x.value.limbs, j->x, zinv2);
    fe_mul(p.y.value.limbs, j->y, zinv3);
    p.infinity = 0;
    return p;
}

static ECPoint point_from_jac(const Jac *j) {
    Fe zinv;
    if (fe_is_zero(j->z)) {
        return ec_point_infinity();
    }
    fe_inv(zinv, j->z);
    return point_from_jac_zinv(j, zinv);
}

/* Converts two points at the price of one inversion. */
static void points_from_jac2(ECPoint *pa, ECPoint *pb, const Jac *a, const Jac *b) {
    Fe product, inv, zinv;
    if (fe_is_zero(a->z) || fe_is_zero(b->z)) {
        *pa = point_from_jac(a);
        *pb = point_from_jac(b);
        return;
    }
    fe_mul(product, a->z, b->z);
    fe_inv(inv, product);
    fe_mul(zinv, inv, b->z);
    *pa = point_from_jac_zinv(a, zinv);
    fe_mul(zinv, inv, a->z);
    *pb = point_from_jac_zinv(b, zinv);
}

ECPoint ec_point_add(ECPoint p, ECPoint q) {
    Jac a, b, sum;
    if (p.infinity) {
        return q;
    }
    if (q.infinity) {
        return p;
    }
    jac_from_point(&a, &p);
    jac_from_point(&b, &q);
    jac_add_vt(&sum, &a, &b);
    return point_from_jac(&sum);
}

ECPoint ec_point_multiply(ECPoint p, const BigInt256 *k) {
    Jac base, result;
    if (bigint256_is_zero(k) || p.infinity) {
        return ec_point_infinity();
    }
    if (bigint256_is_one(k)) {
        return p;
    }
    jac_from_point(&base, &p);
    if (fe_equal(base.x, EC_GX) && fe_equal(base.y, EC_GY)) {
        ec_mul_g(&result, k->limbs);
    } else {
        ec_mul_ct(&result, &base, k->limbs);
    }
    return point_from_jac(&result);
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

static BigInt256 random_scalar(void) {
    for (;;) {
        BigInt256 k = random_bigint();
        if (!bigint256_is_zero(&k) && bigint256_compare(&k, &SM2_N) < 0) {
            return k;
        }
    }
}

static void user_sm3_z(const char *user_id, const ECPoint *pub, uint8_t z[32]) {
    SM3 sm3;
    uint8_t buf[192];
    size_t uid_len = strlen(user_id);
    uint16_t entl = (uint16_t)(uid_len * 8);
    uint8_t entl_bytes[2];
    FpElement gx, gy;

    fe_copy(gx.value.limbs, EC_GX);
    fe_copy(gy.value.limbs, EC_GY);
    fp_to_be_bytes(&SM2_A, buf);
    fp_to_be_bytes(&SM2_B, buf + 32);
    fp_to_be_bytes(&gx, buf + 64);
    fp_to_be_bytes(&gy, buf + 96);
    fp_to_be_bytes(&pub->x, buf + 128);
    fp_to_be_bytes(&pub->y, buf + 160);

    entl_bytes[0] = (uint8_t)(entl >> 8);
    entl_bytes[1] = (uint8_t)entl;
    sm3_init(&sm3);
    sm3_update(&sm3, entl_bytes, 2);
    sm3_update(&sm3, (const uint8_t *)user_id, uid_len);
    sm3_update(&sm3, buf, sizeof(buf));
    smx_sm3_finish_bytes(&sm3, z);
}

/* e = SM3(Z || M) as an integer */
static BigInt256 message_digest(const uint8_t z[32], const char *message) {
    SM3 sm3;
    uint8_t digest[32];
    sm3_init(&sm3);
    sm3_update(&sm3, z, 32);
    sm3_update(&sm3, (const uint8_t *)message, strlen(message));
    smx_sm3_finish_bytes(&sm3, digest);
    return bigint256_from_be_bytes(digest, 32);
}

/*
 * KDF(prefix, keylen) = SM3(prefix || ct) for ct = 1, 2, ... Every prefix used in
 * SM2 is a whole number of SM3 blocks, so it is absorbed once and each output
 * block then costs exactly one compression.
 */
typedef struct {
    uint32_t state[8];
    uint32_t counter;
    uint64_t total_bits;
} Kdf;

static void kdf_init(Kdf *kdf, const uint8_t *prefix, size_t blocks) {
    SM3 sm3;
    sm3_init(&sm3);
    memcpy(kdf->state, sm3.v, sizeof(kdf->state));
    smx_sm3_compress(kdf->state, prefix, blocks);
    kdf->counter = 1;
    kdf->total_bits = ((uint64_t)blocks * 64 + 4) * 8;
}

static void kdf_next(Kdf *kdf, uint8_t out[32]) {
    uint32_t v[8];
    uint8_t block[64];
    int i;
    memset(block, 0, sizeof(block));
    smx_store_be32(block, kdf->counter++);
    block[4] = 0x80;
    smx_store_be64(block + 56, kdf->total_bits);
    memcpy(v, kdf->state, sizeof(v));
    smx_sm3_compress(v, block, 1);
    for (i = 0; i < 8; i++) {
        smx_store_be32(out + i * 4, v[i]);
    }
}

static void kdf_init_point(Kdf *kdf, const ECPoint *p) {
    uint8_t xy[64];
    fp_to_be_bytes(&p->x, xy);
    fp_to_be_bytes(&p->y, xy + 32);
    kdf_init(kdf, xy, 1);
}

static void kdf_key_swap(int keylen, const ECPoint *vu, const uint8_t *za, const uint8_t *zb,
                         uint8_t *out) {
    uint8_t prefix[128], block[32];
    Kdf kdf;
    int off;
    fp_to_be_bytes(&vu->x, prefix);
    fp_to_be_bytes(&vu->y, prefix + 32);
    memcpy(prefix + 64, za, 32);
    memcpy(prefix + 96, zb, 32);
    kdf_init(&kdf, prefix, 2);
    for (off = 0; off < keylen; off += 32) {
        size_t n = keylen - off < 32 ? (size_t)(keylen - off) : 32;
        kdf_next(&kdf, block);
        memcpy(out + off, block, n);
    }
}

static BigInt256 calc_x(const BigInt256 *x) {
    BigInt256 r;
    r.limbs[0] = x->limbs[0];
    r.limbs[1] = x->limbs[1] | ((uint64_t)1 << 63);
    r.limbs[2] = 0;
    r.limbs[3] = 0;
    return r;
}

static BigInt256 calc_t(const BigInt256 *r, const BigInt256 *d, const BigInt256 *x_) {
    BigInt256 xr, result;
    fn_mul(xr.limbs, x_->limbs, r->limbs);
    bigint256_mod_add(&result, d, &xr, &SM2_N);
    return result;
}

/*
 * t * (p + x_ * r). x_ comes from the peer's public ephemeral point, so the inner
 * product may use the faster variable-time path; t is secret.
 */
static ECPoint calc_point(const BigInt256 *t, const BigInt256 *x_, const ECPoint *p,
                          const ECPoint *r) {
    Jac jp, jr, sum;
    if (bigint256_is_zero(t)) {
        return ec_point_infinity();
    }
    jac_from_point(&jp, p);
    jac_from_point(&jr, r);
    ec_mul_vt(&sum, &jr, x_->limbs);
    jac_add_vt(&sum, &jp, &sum);
    ec_mul_ct(&sum, &sum, t->limbs);
    return point_from_jac(&sum);
}

static void create_s(uint8_t tag, const ECPoint *vu, const uint8_t *za, const uint8_t *zb,
                     const ECPoint *ra, const ECPoint *rb, uint8_t out[32]) {
    SM3 sm3;
    uint8_t buf[32], h1[32], first[1];
    fp_to_be_bytes(&vu->x, buf);
    sm3_init(&sm3);
    sm3_update(&sm3, buf, 32);
    sm3_update(&sm3, za, 32);
    sm3_update(&sm3, zb, 32);
    fp_to_be_bytes(&ra->x, buf);
    sm3_update(&sm3, buf, 32);
    fp_to_be_bytes(&ra->y, buf);
    sm3_update(&sm3, buf, 32);
    fp_to_be_bytes(&rb->x, buf);
    sm3_update(&sm3, buf, 32);
    fp_to_be_bytes(&rb->y, buf);
    sm3_update(&sm3, buf, 32);
    smx_sm3_finish_bytes(&sm3, h1);

    first[0] = tag;
    fp_to_be_bytes(&vu->y, buf);
    sm3_update(&sm3, first, 1);
    sm3_update(&sm3, buf, 32);
    sm3_update(&sm3, h1, 32);
    smx_sm3_finish_bytes(&sm3, out);
}

/* Constant-time comparison: the running time does not depend on where a difference is. */
static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

/* ========== SM2 Public API ========== */

ECPoint sm2_get_public_key(const BigInt256 *private_key) {
    Jac r;
    ec_mul_g(&r, private_key->limbs);
    return point_from_jac(&r);
}

void sm2_gen_keypair(char pri_hex[65], char pub_hex[131]) {
    BigInt256 priv = random_scalar();
    ECPoint pub = sm2_get_public_key(&priv);
    bigint256_to_hex(&priv, pri_hex);
    ec_point_to_hex_encoded(&pub, pub_hex);
}

char *sm2_encrypt(const char *plaintext, const char *public_key_hex) {
    size_t msg_len = strlen(plaintext);
    ECPoint pub;
    Jac base;
    char *result;

    if (msg_len == 0) {
        return NULL;
    }
    pub = ec_point_from_hex_encoded(public_key_hex);
    if (!ec_point_is_on_curve(&pub)) {
        return NULL;
    }
    /* C1 (130 hex) || C3 (64 hex) || C2 (2 * msg_len hex) */
    result = (char *)malloc(130 + 64 + msg_len * 2 + 1);
    if (result == NULL) {
        return NULL;
    }
    jac_from_point(&base, &pub);

    for (;;) {
        BigInt256 k = random_scalar();
        Jac jc1, jp2;
        ECPoint c1, p2;
        Kdf kdf;
        SM3 sm3;
        uint8_t key[32], c3[32], coord[32];
        uint8_t any_key_bit = 0;
        char *out = result + 130 + 64;
        size_t off;

        ec_mul_g(&jc1, k.limbs);
        ec_mul_ct(&jp2, &base, k.limbs);
        points_from_jac2(&c1, &p2, &jc1, &jp2);
        if (p2.infinity) {
            continue;
        }

        kdf_init_point(&kdf, &p2);
        for (off = 0; off < msg_len; off += 32) {
            size_t n = msg_len - off < 32 ? msg_len - off : 32;
            uint8_t c2[32];
            size_t i;
            kdf_next(&kdf, key);
            for (i = 0; i < n; i++) {
                any_key_bit |= key[i];
                c2[i] = (uint8_t)(((uint8_t)plaintext[off + i]) ^ key[i]);
            }
            smx_hex_encode(c2, n, out + off * 2, 'a');
        }
        if (any_key_bit == 0) {
            continue;
        }

        /* C3 = SM3(x2 || M || y2) */
        sm3_init(&sm3);
        fp_to_be_bytes(&p2.x, coord);
        sm3_update(&sm3, coord, 32);
        sm3_update(&sm3, (const uint8_t *)plaintext, msg_len);
        fp_to_be_bytes(&p2.y, coord);
        sm3_update(&sm3, coord, 32);
        smx_sm3_finish_bytes(&sm3, c3);

        {
            char c1_hex[131];
            ec_point_to_hex_encoded(&c1, c1_hex);
            memcpy(result, c1_hex, 130);
        }
        smx_hex_encode(c3, 32, result + 130, 'a');
        result[130 + 64 + msg_len * 2] = '\0';
        return result;
    }
}

char *sm2_decrypt(const char *ciphertext_hex, const char *private_key_hex) {
    size_t ct_len = strlen(ciphertext_hex);
    char c1_hex[131], c3_hex[65];
    uint8_t c3[32], computed[32], key[32], coord[32];
    const char *c2_hex;
    size_t c2_len, off;
    uint8_t *plain;
    ECPoint c1, p2;
    BigInt256 d;
    Kdf kdf;
    SM3 sm3;

    if (ct_len < 130 + 64) {
        return NULL;
    }
    memcpy(c1_hex, ciphertext_hex, 130);
    c1_hex[130] = '\0';
    c1 = ec_point_from_hex_encoded(c1_hex);
    if (!ec_point_is_on_curve(&c1)) {
        return NULL;
    }

    d = bigint256_from_hex(private_key_hex);
    p2 = ec_point_multiply(c1, &d);
    if (p2.infinity) {
        return NULL;
    }

    memcpy(c3_hex, ciphertext_hex + 130, 64);
    c3_hex[64] = '\0';
    memset(c3, 0, sizeof(c3));
    hex_to_bytes(c3_hex, c3, sizeof(c3));

    c2_hex = ciphertext_hex + 194;
    c2_len = (ct_len - 194) / 2;
    plain = (uint8_t *)malloc(c2_len + 1);
    if (plain == NULL) {
        return NULL;
    }
    /* a 0x prefix makes the decode one byte short */
    plain[c2_len] = '\0';
    if (c2_len > 0) {
        plain[c2_len - 1] = 0;
    }
    hex_to_bytes(c2_hex, plain, c2_len);

    kdf_init_point(&kdf, &p2);
    for (off = 0; off < c2_len; off += 32) {
        size_t n = c2_len - off < 32 ? c2_len - off : 32;
        size_t i;
        kdf_next(&kdf, key);
        for (i = 0; i < n; i++) {
            plain[off + i] ^= key[i];
        }
    }

    /* verify C3 */
    sm3_init(&sm3);
    fp_to_be_bytes(&p2.x, coord);
    sm3_update(&sm3, coord, 32);
    sm3_update(&sm3, plain, c2_len);
    fp_to_be_bytes(&p2.y, coord);
    sm3_update(&sm3, coord, 32);
    smx_sm3_finish_bytes(&sm3, computed);

    if (!bytes_equal(computed, c3, 32)) {
        free(plain);
        return NULL;
    }
    return (char *)plain;
}

char *sm2_sign(const char *user_id, const char *message, const char *private_key_hex) {
    BigInt256 d = bigint256_from_hex(private_key_hex);
    BigInt256 one = bigint256_one();
    BigInt256 d_plus_1, d_plus_1_inv, e, k;
    Jac jpub, jr;
    ECPoint pub, kp;
    uint8_t z[32];
    int first = 1;

    /* the first nonce is drawn up front so both points can share one inversion */
    k = random_scalar();
    ec_mul_g(&jpub, d.limbs);
    ec_mul_g(&jr, k.limbs);
    points_from_jac2(&pub, &kp, &jpub, &jr);

    user_sm3_z(user_id, &pub, z);
    e = message_digest(z, message);

    bigint256_add(&d_plus_1, &d, &one);
    fn_inv(d_plus_1_inv.limbs, d_plus_1.limbs);

    for (;;) {
        BigInt256 r, rk, rd, k_minus_rd, s;
        uint64_t carry;
        char *sig;

        if (!first) {
            k = random_scalar();
            ec_mul_g(&jr, k.limbs);
            kp = point_from_jac(&jr);
        }
        first = 0;

        bigint256_mod_add(&r, &e, &kp.x.value, &SM2_N);
        if (bigint256_is_zero(&r)) {
            continue;
        }
        carry = bigint256_add(&rk, &r, &k);
        if (carry == 0 && bigint256_compare(&rk, &SM2_N) == 0) {
            continue;
        }

        fn_mul(rd.limbs, r.limbs, d.limbs);
        bigint256_mod_sub(&k_minus_rd, &k, &rd, &SM2_N);
        fn_mul(s.limbs, k_minus_rd.limbs, d_plus_1_inv.limbs);
        if (bigint256_is_zero(&s)) {
            continue;
        }

        /* format: r_hex + "h" + s_hex */
        sig = (char *)malloc(64 + 1 + 64 + 1);
        if (sig == NULL) {
            return NULL;
        }
        bigint256_to_hex_lower(&r, sig);
        sig[64] = 'h';
        bigint256_to_hex_lower(&s, sig + 65);
        return sig;
    }
}

int sm2_verify(const char *user_id, const char *signature, const char *message,
               const char *public_key_hex) {
    const char *h_pos = strchr(signature, 'h');
    char r_str[65], s_str[65];
    size_t r_len, s_len;
    BigInt256 r, s, e, t, candidate, sum;
    ECPoint pub;
    Jac base, point;
    Fe zz, expected;
    uint8_t z[32];
    uint64_t borrow, carry;

    if (h_pos == NULL) {
        return 0;
    }
    r_len = (size_t)(h_pos - signature);
    if (r_len > 64) {
        return 0;
    }
    memcpy(r_str, signature, r_len);
    r_str[r_len] = '\0';
    s_len = strlen(h_pos + 1);
    if (s_len > 64) {
        return 0;
    }
    memcpy(s_str, h_pos + 1, s_len);
    s_str[s_len] = '\0';

    r = bigint256_from_hex(r_str);
    s = bigint256_from_hex(s_str);
    if (bigint256_is_zero(&r) || bigint256_compare(&r, &SM2_N) >= 0) {
        return 0;
    }
    if (bigint256_is_zero(&s) || bigint256_compare(&s, &SM2_N) >= 0) {
        return 0;
    }

    pub = ec_point_from_hex_encoded(public_key_hex);
    if (!ec_point_is_on_curve(&pub)) {
        return 0;
    }

    user_sm3_z(user_id, &pub, z);
    e = message_digest(z, message);

    bigint256_mod_add(&t, &r, &s, &SM2_N);
    if (bigint256_is_zero(&t)) {
        return 0;
    }

    jac_from_point(&base, &pub);
    ec_double_mul_vt(&point, s.limbs, t.limbs, &base);
    if (fe_is_zero(point.z)) {
        return 0;
    }

    /*
     * The check is r == (e + x) mod n, with x the affine coordinate. To avoid
     * inverting Z, solve for the x values that would satisfy it and compare
     * X == x * Z^2. mod_add gives e + x when that is below n, and e + x - n
     * otherwise, so the only candidates are r - e and r + n - e.
     */
    fe_sqr(zz, point.z);
    borrow = bigint256_sub(&candidate, &r, &e);
    if (!borrow) {
        fe_mul(expected, candidate.limbs, zz);
        if (fe_equal(expected, point.x)) {
            return 1;
        }
    }
    carry = bigint256_add(&sum, &r, &SM2_N);
    borrow = bigint256_sub(&candidate, &sum, &e);
    if (carry == borrow && bigint256_compare(&candidate, &SM2_P) < 0) {
        fe_mul(expected, candidate.limbs, zz);
        if (fe_equal(expected, point.x)) {
            return 1;
        }
    }
    return 0;
}

/* ========== SM2 Key Exchange ========== */

SM2KeySwapParams sm2_get_sb(int byte_len, ECPoint pA, ECPoint rA, ECPoint pB, const BigInt256 *dB,
                            ECPoint rB, const BigInt256 *rb, const char *idA, const char *idB) {
    SM2KeySwapParams result;
    BigInt256 x2_, tb, x1_;
    ECPoint v;
    uint8_t *kb;
    uint8_t sb[32];

    memset(&result, 0, sizeof(result));

    x2_ = calc_x(&rB.x.value);
    tb = calc_t(rb, dB, &x2_);

    if (!ec_point_is_on_curve(&rA)) {
        strcpy(result.message, "RA point is not on curve");
        return result;
    }

    x1_ = calc_x(&rA.x.value);
    v = calc_point(&tb, &x1_, &pA, &rA);
    if (v.infinity) {
        strcpy(result.message, "V is point at infinity");
        return result;
    }

    user_sm3_z(idA, &pA, result.za);
    user_sm3_z(idB, &pB, result.zb);

    kb = (uint8_t *)malloc((size_t)byte_len);
    kdf_key_swap(byte_len, &v, result.za, result.zb, kb);

    create_s(0x02, &v, result.za, result.zb, &rA, &rB, sb);

    bytes_to_hex(sb, 32, result.sb);
    bytes_to_hex(kb, (size_t)byte_len, result.kb);
    free(kb);

    result.v = v;
    result.success = 1;
    return result;
}

SM2KeySwapParams sm2_get_sa(int byte_len, ECPoint pB, ECPoint rB, ECPoint pA, const BigInt256 *dA,
                            ECPoint rA, const BigInt256 *ra, const char *idA, const char *idB,
                            const uint8_t *sb, size_t sb_len) {
    SM2KeySwapParams result;
    BigInt256 x1_, ta, x2_;
    ECPoint u;
    uint8_t za[32], zb[32], s1[32], sa[32];
    uint8_t *ka;

    memset(&result, 0, sizeof(result));

    x1_ = calc_x(&rA.x.value);
    ta = calc_t(ra, dA, &x1_);

    if (!ec_point_is_on_curve(&rB)) {
        strcpy(result.message, "RB point is not on curve");
        return result;
    }

    x2_ = calc_x(&rB.x.value);
    u = calc_point(&ta, &x2_, &pB, &rB);
    if (u.infinity) {
        strcpy(result.message, "U is point at infinity");
        return result;
    }

    user_sm3_z(idA, &pA, za);
    user_sm3_z(idB, &pB, zb);

    ka = (uint8_t *)malloc((size_t)byte_len);
    kdf_key_swap(byte_len, &u, za, zb, ka);

    create_s(0x02, &u, za, zb, &rA, &rB, s1);

    if (!bytes_equal(s1, sb, sb_len < 32 ? sb_len : 32)) {
        free(ka);
        strcpy(result.message, "B's verification value does not match");
        return result;
    }

    create_s(0x03, &u, za, zb, &rA, &rB, sa);

    bytes_to_hex(sa, 32, result.sa);
    bytes_to_hex(ka, (size_t)byte_len, result.ka);
    free(ka);

    result.success = 1;
    return result;
}

int sm2_check_sa(ECPoint v, const uint8_t *za, const uint8_t *zb, ECPoint rA, ECPoint rB,
                 const uint8_t *sa, size_t sa_len) {
    uint8_t s2[32];
    create_s(0x03, &v, za, zb, &rA, &rB, s2);
    return bytes_equal(s2, sa, sa_len < 32 ? sa_len : 32);
}
