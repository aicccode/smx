/* getrandom/getentropy and open() are not in strict C99 headers. */
#if !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE 1
#endif
#if !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#include "sm2_ec.h"
#include "sm2_fn.h"
#include "smx_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/random.h>
#include <unistd.h>
#endif

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
    return a != NULL && bigint256_is_zero(&a->value);
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
    if (a != NULL) {
        bigint256_to_be_bytes(&a->value, out);
    }
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

/* x, y < p and on the curve; the coordinates must already be canonical. */
static int point_coords_on_curve(const Fe x, const Fe y) {
    Fe lhs, rhs;
    /* y^2 = (x^2 + a) * x + b */
    fe_sqr(lhs, y);
    fe_sqr(rhs, x);
    fe_add(rhs, rhs, SM2_A.value.limbs);
    fe_mul(rhs, rhs, x);
    fe_add(rhs, rhs, SM2_B.value.limbs);
    return fe_equal(lhs, rhs) != 0;
}

static int fe_is_canonical(const Fe a) {
    uint64_t b;
    (void)smx_subb(a[0], FE_P[0], 0, &b);
    (void)smx_subb(a[1], FE_P[1], b, &b);
    (void)smx_subb(a[2], FE_P[2], b, &b);
    (void)smx_subb(a[3], FE_P[3], b, &b);
    return b != 0;
}

/* A finite point of the group: what every entry point requires of a key. */
static int point_is_valid(const ECPoint *p) {
    return !p->infinity && fe_is_canonical(p->x.value.limbs) && fe_is_canonical(p->y.value.limbs) &&
           point_coords_on_curve(p->x.value.limbs, p->y.value.limbs);
}

ECPoint ec_point_from_hex_encoded(const char *hex) {
    uint8_t data[65];
    ECPoint p;

    if (hex == NULL || strlen(hex) != 130 || !smx_hex_decode(hex, 65, data) || data[0] != 0x04) {
        return ec_point_infinity();
    }
    p.x.value = bigint256_from_be_bytes(data + 1, 32);
    p.y.value = bigint256_from_be_bytes(data + 33, 32);
    p.infinity = 0;
    return point_is_valid(&p) ? p : ec_point_infinity();
}

void ec_point_to_hex_encoded(const ECPoint *p, char out[131]) {
    uint8_t encoded[65];
    if (p == NULL || out == NULL) {
        return;
    }
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
    return p != NULL && point_is_valid(p);
}

/* ---- conversions between the public affine type and Jacobian ---- */

static void jac_from_point(Jac *r, const ECPoint *p) {
    if (p->infinity) {
        jac_set_infinity(r);
        return;
    }
    jac_set_affine(r, p->x.value.limbs, p->y.value.limbs);
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
    /* Z = 0 only for a scalar that is 0 mod n, which is invalid input */
    uint64_t at_infinity = fe_is_zero(j->z);
    SMX_DECLASSIFY(&at_infinity, sizeof(at_infinity));
    if (at_infinity) {
        return ec_point_infinity();
    }
    fe_inv(zinv, j->z);
    return point_from_jac_zinv(j, zinv);
}

/* Converts two points at the price of one inversion. */
static void points_from_jac2(ECPoint *pa, ECPoint *pb, const Jac *a, const Jac *b) {
    Fe product, inv, zinv;
    uint64_t at_infinity = fe_is_zero(a->z) | fe_is_zero(b->z);
    SMX_DECLASSIFY(&at_infinity, sizeof(at_infinity));
    if (at_infinity) {
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
    if ((!p.infinity && !point_is_valid(&p)) || (!q.infinity && !point_is_valid(&q))) {
        return ec_point_infinity();
    }
    if (p.infinity) {
        return q.infinity ? ec_point_infinity() : q;
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
    ECPoint out;
    if (k == NULL || !point_is_valid(&p)) {
        return ec_point_infinity();
    }
    jac_from_point(&base, &p);
    if (fe_equal(base.x, EC_GX) && fe_equal(base.y, EC_GY)) {
        ec_mul_g(&result, k->limbs);
    } else {
        ec_mul_ct(&result, &base, k->limbs);
    }
    out = point_from_jac(&result);
    smx_wipe(&result, sizeof(result));
    return out;
}

/* ========== SM2 internal helpers ========== */

#define SM2_MAX_USER_ID 8191
/* A KDF counter of 32 bits gives at most this many output bytes */
#define SM2_MAX_KDF_BYTES (((uint64_t)0xFFFFFFFFu) * 32)
/* What the 513-character ka and kb fields of SM2KeySwapParams can hold */
#define SM2_MAX_KX_BYTES 256

/* Upper limit on rejected draws. A correct RNG fails 256 in a row with chance 2^-8192. */
#define SM2_MAX_RETRIES 256

/*
 * Fills buf from the operating system's CSPRNG; returns 1, or 0 if it could not. There is
 * no state in this process, so fork() cannot duplicate any output. There is no fallback:
 * an unsupported platform gets a clean failure.
 */
static int random_bytes(uint8_t *buf, size_t len) {
#if defined(SMX_TEST_RNG_FAILS)
    (void)buf;
    (void)len;
    return 0;
#elif defined(SMX_TEST_RNG_ALL_ONES)
    memset(buf, 0xFF, len);
    return 1;
#elif defined(__linux__) && defined(SYS_getrandom)
    size_t off = 0;
    int have_syscall = 1;
    while (off < len) {
        long n = syscall(SYS_getrandom, buf + off, len - off, 0);
        if (n > 0) {
            off += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else if (n < 0 && errno == ENOSYS) {
            have_syscall = 0; /* kernels before 3.17 */
            break;
        } else {
            smx_wipe(buf, len);
            return 0;
        }
    }
    if (have_syscall) {
        return 1;
    }
#elif (defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__))
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off < 256 ? len - off : 256;
        if (getentropy(buf + off, chunk) != 0) {
            smx_wipe(buf, len);
            return 0;
        }
        off += chunk;
    }
    return 1;
#endif
#if defined(__linux__) && !defined(SMX_TEST_RNG_FAILS) && !defined(SMX_TEST_RNG_ALL_ONES)
    {
        size_t got = 0;
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            return 0;
        }
        while (got < len) {
            ssize_t n = read(fd, buf + got, len - got);
            if (n > 0) {
                got += (size_t)n;
            } else if (n < 0 && errno == EINTR) {
                continue;
            } else {
                close(fd);
                smx_wipe(buf, len);
                return 0;
            }
        }
        close(fd);
        return 1;
    }
#elif !(defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)) &&                     \
    !defined(SMX_TEST_RNG_FAILS) && !defined(SMX_TEST_RNG_ALL_ONES)
    (void)buf;
    (void)len;
    return 0;
#endif
}

/*
 * A uniform scalar in [1, max], by rejection sampling, so with no modulo bias. Returns 0
 * if the RNG failed or every draw was rejected.
 */
static int random_scalar(BigInt256 *out, const BigInt256 *max) {
    int attempt;
    for (attempt = 0; attempt < SM2_MAX_RETRIES; attempt++) {
        uint8_t b[32];
        int accept;
        if (!random_bytes(b, 32)) {
            return 0;
        }
        *out = bigint256_from_be_bytes(b, 32);
        smx_wipe(b, sizeof(b));
        /* a rejected draw reveals nothing about the value finally accepted */
        accept = (int)(!bigint256_is_zero(out)) & (int)(bigint256_compare(out, max) <= 0);
        SMX_DECLASSIFY(&accept, sizeof(accept));
        if (accept) {
            return 1;
        }
    }
    smx_wipe(out, sizeof(*out));
    return 0;
}

/* n - 1 and n - 2: the largest nonce and the largest private key. */
static const BigInt256 SM2_N_MINUS_1 = {
    {0x53BBF40939D54122ULL, 0x7203DF6B21C6052BULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL}};
static const BigInt256 SM2_N_MINUS_2 = {
    {0x53BBF40939D54121ULL, 0x7203DF6B21C6052BULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL}};

/* d in [1, n-2]. n - 1 is excluded because signing inverts d + 1. Constant time. */
static int private_key_in_range(const BigInt256 *d) {
    uint64_t in_range = ~smx_mask_is_zero(d->limbs[0] | d->limbs[1] | d->limbs[2] | d->limbs[3]);
    uint64_t b;
    (void)smx_subb(d->limbs[0], SM2_N_MINUS_1.limbs[0], 0, &b);
    (void)smx_subb(d->limbs[1], SM2_N_MINUS_1.limbs[1], b, &b);
    (void)smx_subb(d->limbs[2], SM2_N_MINUS_1.limbs[2], b, &b);
    (void)smx_subb(d->limbs[3], SM2_N_MINUS_1.limbs[3], b, &b);
    in_range &= (uint64_t)0 - b;
    SMX_DECLASSIFY(&in_range, sizeof(in_range));
    return in_range != 0;
}

/* Exactly 64 hex digits, in range. Only the validity of the key can show in the timing. */
static int parse_private_key(const char *hex, BigInt256 *d) {
    uint8_t be[32];
    int ok;
    if (hex == NULL || strlen(hex) != 64) {
        return 0;
    }
    ok = smx_hex_decode(hex, 32, be);
    SMX_DECLASSIFY(&ok, sizeof(ok));
    *d = bigint256_from_be_bytes(be, 32);
    smx_wipe(be, sizeof(be));
    if (!ok || !private_key_in_range(d)) {
        smx_wipe(d, sizeof(*d));
        return 0;
    }
    return 1;
}

static int user_id_is_valid(const char *user_id) {
    size_t i;
    if (user_id == NULL) {
        return 0;
    }
    /* ENTL is 16 bits of bit length; scan no further than the limit */
    for (i = 0; i < SM2_MAX_USER_ID; i++) {
        if (user_id[i] == '\0') {
            return 1;
        }
    }
    return user_id[SM2_MAX_USER_ID] == '\0';
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
static BigInt256 message_digest(const uint8_t z[32], const uint8_t *message, size_t len) {
    SM3 sm3;
    uint8_t digest[32];
    sm3_init(&sm3);
    sm3_update(&sm3, z, 32);
    sm3_update(&sm3, message, len);
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
    smx_wipe(v, sizeof(v));
}

static void kdf_init_point(Kdf *kdf, const ECPoint *p) {
    uint8_t xy[64];
    fp_to_be_bytes(&p->x, xy);
    fp_to_be_bytes(&p->y, xy + 32);
    kdf_init(kdf, xy, 1);
    smx_wipe(xy, sizeof(xy));
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
    smx_wipe(prefix, sizeof(prefix));
    smx_wipe(block, sizeof(block));
    smx_wipe(&kdf, sizeof(kdf));
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
    ECPoint out;
    jac_from_point(&jp, p);
    jac_from_point(&jr, r);
    ec_mul_vt(&sum, &jr, x_->limbs);
    jac_add_vt(&sum, &jp, &sum);
    ec_mul_ct(&sum, &sum, t->limbs);
    out = point_from_jac(&sum);
    smx_wipe(&sum, sizeof(sum));
    return out;
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
    smx_wipe(buf, sizeof(buf));
    smx_wipe(h1, sizeof(h1));
    smx_wipe(&sm3, sizeof(sm3));
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
    ECPoint out;
    if (private_key == NULL || !private_key_in_range(private_key)) {
        return ec_point_infinity();
    }
    ec_mul_g(&r, private_key->limbs);
    out = point_from_jac(&r);
    smx_wipe(&r, sizeof(r));
    return out;
}

void sm2_gen_keypair(char pri_hex[65], char pub_hex[131]) {
    BigInt256 priv;
    if (pri_hex == NULL || pub_hex == NULL) {
        return;
    }
    pri_hex[0] = '\0';
    pub_hex[0] = '\0';
    if (random_scalar(&priv, &SM2_N_MINUS_2)) {
        ECPoint pub = sm2_get_public_key(&priv);
        bigint256_to_hex(&priv, pri_hex);
        ec_point_to_hex_encoded(&pub, pub_hex);
        smx_wipe(&priv, sizeof(priv));
    }
}

char *sm2_encrypt_bytes(const uint8_t *data, size_t msg_len, const char *public_key_hex) {
    ECPoint pub;
    Jac base;
    char *result;
    int attempt;

    if (data == NULL || msg_len == 0 || public_key_hex == NULL) {
        return NULL;
    }
    /* the KDF counter must not wrap, and the output length must not overflow */
    if ((uint64_t)msg_len > SM2_MAX_KDF_BYTES || msg_len > (SIZE_MAX - (130 + 64 + 1)) / 2) {
        return NULL;
    }
    pub = ec_point_from_hex_encoded(public_key_hex);
    if (pub.infinity) {
        return NULL;
    }
    /* C1 (130 hex) || C3 (64 hex) || C2 (2 * msg_len hex) */
    result = (char *)malloc(130 + 64 + msg_len * 2 + 1);
    if (result == NULL) {
        return NULL;
    }
    jac_from_point(&base, &pub);

    for (attempt = 0; attempt < SM2_MAX_RETRIES; attempt++) {
        BigInt256 k;
        Jac jc1, jp2;
        ECPoint c1, p2;
        Kdf kdf;
        SM3 sm3;
        uint8_t key[32], c2[32], c3[32], coord[32];
        uint8_t any_key_bit = 0;
        char *out = result + 130 + 64;
        size_t off;
        char c1_hex[131];

        if (!random_scalar(&k, &SM2_N_MINUS_1)) {
            break;
        }
        ec_mul_g(&jc1, k.limbs);
        ec_mul_ct(&jp2, &base, k.limbs);
        smx_wipe(&k, sizeof(k));
        points_from_jac2(&c1, &p2, &jc1, &jp2);
        smx_wipe(&jp2, sizeof(jp2));
        if (p2.infinity || c1.infinity) {
            continue;
        }

        kdf_init_point(&kdf, &p2);
        for (off = 0; off < msg_len; off += 32) {
            size_t n = msg_len - off < 32 ? msg_len - off : 32;
            size_t i;
            kdf_next(&kdf, key);
            for (i = 0; i < n; i++) {
                any_key_bit |= key[i];
                c2[i] = (uint8_t)(data[off + i] ^ key[i]);
            }
            smx_hex_encode(c2, n, out + off * 2, 'a');
        }
        smx_wipe(key, sizeof(key));
        smx_wipe(c2, sizeof(c2));
        smx_wipe(&kdf, sizeof(kdf));
        SMX_DECLASSIFY(&any_key_bit, sizeof(any_key_bit));
        if (any_key_bit == 0) {
            smx_wipe(&p2, sizeof(p2));
            continue;
        }

        /* C3 = SM3(x2 || M || y2) */
        sm3_init(&sm3);
        fp_to_be_bytes(&p2.x, coord);
        sm3_update(&sm3, coord, 32);
        sm3_update(&sm3, data, msg_len);
        fp_to_be_bytes(&p2.y, coord);
        sm3_update(&sm3, coord, 32);
        smx_sm3_finish_bytes(&sm3, c3);
        smx_wipe(&p2, sizeof(p2));
        smx_wipe(coord, sizeof(coord));
        smx_wipe(&sm3, sizeof(sm3));

        ec_point_to_hex_encoded(&c1, c1_hex);
        memcpy(result, c1_hex, 130);
        smx_hex_encode(c3, 32, result + 130, 'a');
        result[130 + 64 + msg_len * 2] = '\0';
        return result;
    }
    smx_wipe(result, 130 + 64 + msg_len * 2);
    free(result);
    return NULL;
}

char *sm2_encrypt(const char *plaintext, const char *public_key_hex) {
    if (plaintext == NULL) {
        return NULL;
    }
    return sm2_encrypt_bytes((const uint8_t *)plaintext, strlen(plaintext), public_key_hex);
}

uint8_t *sm2_decrypt_bytes(const char *ciphertext_hex, const char *private_key_hex,
                           size_t *out_len) {
    size_t ct_len, c2_len, off;
    char c1_hex[131];
    uint8_t c3[32], computed[32], key[32], coord[32];
    uint8_t any_key_bit = 0;
    uint8_t *plain;
    ECPoint c1, p2;
    BigInt256 d;
    Jac base, shared;
    Kdf kdf;
    SM3 sm3;
    int match, zero_key;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (ciphertext_hex == NULL || private_key_hex == NULL) {
        return NULL;
    }
    ct_len = strlen(ciphertext_hex);
    /* C2 must hold at least one byte, and be whole bytes */
    if (ct_len < 130 + 64 + 2 || (ct_len & 1) != 0) {
        return NULL;
    }
    c2_len = (ct_len - 194) / 2;
    if ((uint64_t)c2_len > SM2_MAX_KDF_BYTES) {
        return NULL;
    }
    memcpy(c1_hex, ciphertext_hex, 130);
    c1_hex[130] = '\0';
    c1 = ec_point_from_hex_encoded(c1_hex);
    if (c1.infinity || !smx_hex_decode(ciphertext_hex + 130, 32, c3)) {
        return NULL;
    }
    plain = (uint8_t *)malloc(c2_len + 1);
    if (plain == NULL) {
        return NULL;
    }
    if (!smx_hex_decode(ciphertext_hex + 194, c2_len, plain) ||
        !parse_private_key(private_key_hex, &d)) {
        free(plain);
        return NULL;
    }
    plain[c2_len] = '\0';

    jac_from_point(&base, &c1);
    ec_mul_ct(&shared, &base, d.limbs);
    smx_wipe(&d, sizeof(d));
    p2 = point_from_jac(&shared);
    smx_wipe(&shared, sizeof(shared));

    kdf_init_point(&kdf, &p2);
    for (off = 0; off < c2_len; off += 32) {
        size_t n = c2_len - off < 32 ? c2_len - off : 32;
        size_t i;
        kdf_next(&kdf, key);
        for (i = 0; i < n; i++) {
            any_key_bit |= key[i];
            plain[off + i] ^= key[i];
        }
    }
    smx_wipe(key, sizeof(key));
    smx_wipe(&kdf, sizeof(kdf));

    /* verify C3 */
    sm3_init(&sm3);
    fp_to_be_bytes(&p2.x, coord);
    sm3_update(&sm3, coord, 32);
    sm3_update(&sm3, plain, c2_len);
    fp_to_be_bytes(&p2.y, coord);
    sm3_update(&sm3, coord, 32);
    smx_sm3_finish_bytes(&sm3, computed);
    smx_wipe(&p2, sizeof(p2));
    smx_wipe(coord, sizeof(coord));
    smx_wipe(&sm3, sizeof(sm3));

    match = bytes_equal(computed, c3, 32);
    zero_key = any_key_bit == 0;
    smx_wipe(computed, sizeof(computed));
    SMX_DECLASSIFY(&match, sizeof(match));
    SMX_DECLASSIFY(&zero_key, sizeof(zero_key));
    if (!match || zero_key) {
        smx_wipe(plain, c2_len);
        free(plain);
        return NULL;
    }
    if (out_len != NULL) {
        *out_len = c2_len;
    }
    return plain;
}

char *sm2_decrypt(const char *ciphertext_hex, const char *private_key_hex) {
    return (char *)sm2_decrypt_bytes(ciphertext_hex, private_key_hex, NULL);
}

char *sm2_sign_bytes(const char *user_id, const uint8_t *message, size_t len,
                     const char *private_key_hex) {
    BigInt256 d, d_plus_1, d_plus_1_inv, e, k, one = bigint256_one();
    Jac jpub, jr;
    ECPoint pub, kp;
    uint8_t z[32];
    char *sig;
    int attempt;

    if (!user_id_is_valid(user_id) || (message == NULL && len != 0) ||
        !parse_private_key(private_key_hex, &d)) {
        return NULL;
    }
    sig = (char *)malloc(64 + 1 + 64 + 1);
    if (sig == NULL) {
        smx_wipe(&d, sizeof(d));
        return NULL;
    }

    /* the first nonce is drawn up front so both points can share one inversion */
    if (!random_scalar(&k, &SM2_N_MINUS_1)) {
        goto fail;
    }
    ec_mul_g(&jpub, d.limbs);
    ec_mul_g(&jr, k.limbs);
    points_from_jac2(&pub, &kp, &jpub, &jr);
    SMX_DECLASSIFY(&pub, sizeof(pub));
    SMX_DECLASSIFY(&kp, sizeof(kp)); /* x1 determines r, which is published */

    user_sm3_z(user_id, &pub, z);
    e = message_digest(z, message, len);
    fn_reduce(e.limbs, e.limbs);

    /* d <= n - 2, so d + 1 is a nonzero value below n and has an inverse */
    bigint256_add(&d_plus_1, &d, &one);
    fn_inv(d_plus_1_inv.limbs, d_plus_1.limbs);

    for (attempt = 0; attempt < SM2_MAX_RETRIES; attempt++) {
        BigInt256 x1, r, rk, rd, k_minus_rd, s;
        uint64_t carry;
        int reject;

        if (attempt != 0) {
            if (!random_scalar(&k, &SM2_N_MINUS_1)) {
                break;
            }
            ec_mul_g(&jr, k.limbs);
            kp = point_from_jac(&jr);
            SMX_DECLASSIFY(&kp, sizeof(kp));
        }

        /* r = (e + x1) mod n, fully reduced; x1 is below p, which can exceed n */
        fn_reduce(x1.limbs, kp.x.value.limbs);
        bigint256_mod_add(&r, &e, &x1, &SM2_N);
        carry = bigint256_add(&rk, &r, &k);
        /* r + k involves the nonce: no short-circuit, so no branch on its carry */
        reject = bigint256_is_zero(&r) | ((int)(carry ^ 1) & (bigint256_compare(&rk, &SM2_N) == 0));
        smx_wipe(&rk, sizeof(rk));
        SMX_DECLASSIFY(&reject, sizeof(reject));
        if (reject) {
            continue;
        }

        fn_mul(rd.limbs, r.limbs, d.limbs);
        bigint256_mod_sub(&k_minus_rd, &k, &rd, &SM2_N);
        fn_mul(s.limbs, k_minus_rd.limbs, d_plus_1_inv.limbs);
        smx_wipe(&rd, sizeof(rd));
        smx_wipe(&k_minus_rd, sizeof(k_minus_rd));
        SMX_DECLASSIFY(&r, sizeof(r));
        SMX_DECLASSIFY(&s, sizeof(s));
        if (bigint256_is_zero(&s)) {
            continue;
        }

        /* format: r_hex + "h" + s_hex */
        bigint256_to_hex_lower(&r, sig);
        sig[64] = 'h';
        bigint256_to_hex_lower(&s, sig + 65);
        smx_wipe(&d, sizeof(d));
        smx_wipe(&k, sizeof(k));
        smx_wipe(&d_plus_1, sizeof(d_plus_1));
        smx_wipe(&d_plus_1_inv, sizeof(d_plus_1_inv));
        smx_wipe(&jr, sizeof(jr));
        smx_wipe(&kp, sizeof(kp));
        return sig;
    }

fail:
    smx_wipe(&d, sizeof(d));
    smx_wipe(&k, sizeof(k));
    smx_wipe(&d_plus_1, sizeof(d_plus_1));
    smx_wipe(&d_plus_1_inv, sizeof(d_plus_1_inv));
    smx_wipe(&jr, sizeof(jr));
    smx_wipe(&kp, sizeof(kp));
    free(sig);
    return NULL;
}

char *sm2_sign(const char *user_id, const char *message, const char *private_key_hex) {
    if (message == NULL) {
        return NULL;
    }
    return sm2_sign_bytes(user_id, (const uint8_t *)message, strlen(message), private_key_hex);
}

/* Exactly 64 hex digits. */
static int parse_signature_scalar(const char *hex, BigInt256 *out) {
    uint8_t be[32];
    if (!smx_hex_decode(hex, 32, be)) {
        return 0;
    }
    *out = bigint256_from_be_bytes(be, 32);
    return !bigint256_is_zero(out) && bigint256_compare(out, &SM2_N) < 0;
}

int sm2_verify_bytes(const char *user_id, const char *signature, const uint8_t *message, size_t len,
                     const char *public_key_hex) {
    BigInt256 r, s, e, t, candidate, sum;
    ECPoint pub;
    Jac base, point;
    Fe zz, expected;
    uint8_t z[32];
    uint64_t carry;

    if (!user_id_is_valid(user_id) || signature == NULL || public_key_hex == NULL ||
        (message == NULL && len != 0)) {
        return 0;
    }
    /* r_hex + "h" + s_hex, each scalar exactly 64 digits */
    if (strlen(signature) != 129 || signature[64] != 'h') {
        return 0;
    }
    if (!parse_signature_scalar(signature, &r) || !parse_signature_scalar(signature + 65, &s)) {
        return 0;
    }

    pub = ec_point_from_hex_encoded(public_key_hex);
    if (pub.infinity) {
        return 0;
    }

    user_sm3_z(user_id, &pub, z);
    e = message_digest(z, message, len);
    fn_reduce(e.limbs, e.limbs);

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
     * The check is r == (e + x) mod n, with x the affine coordinate, in [0, p). To avoid
     * inverting Z, compare X == x * Z^2 for the x values that would satisfy it, which are
     * (r - e) mod n, and that plus n when it is still below p.
     */
    fe_sqr(zz, point.z);
    bigint256_mod_sub(&candidate, &r, &e, &SM2_N);
    fe_mul(expected, candidate.limbs, zz);
    if (fe_equal(expected, point.x)) {
        return 1;
    }
    carry = bigint256_add(&sum, &candidate, &SM2_N);
    if (carry == 0 && bigint256_compare(&sum, &SM2_P) < 0) {
        fe_mul(expected, sum.limbs, zz);
        if (fe_equal(expected, point.x)) {
            return 1;
        }
    }
    return 0;
}

int sm2_verify(const char *user_id, const char *signature, const char *message,
               const char *public_key_hex) {
    if (message == NULL) {
        return 0;
    }
    return sm2_verify_bytes(user_id, signature, (const uint8_t *)message, strlen(message),
                            public_key_hex);
}

/* ========== SM2 Key Exchange ========== */

/* What both sides require before any secret is touched; NULL if it holds. */
static const char *key_swap_input_error(int byte_len, const ECPoint *p_self, const ECPoint *r_self,
                                        const ECPoint *p_peer, const BigInt256 *d,
                                        const BigInt256 *r, const char *id_a, const char *id_b) {
    if (byte_len < 1 || byte_len > SM2_MAX_KX_BYTES) {
        return "Key length out of range";
    }
    if (d == NULL || r == NULL || !private_key_in_range(d) || !private_key_in_range(r)) {
        return "Private value out of range";
    }
    if (!user_id_is_valid(id_a) || !user_id_is_valid(id_b)) {
        return "Invalid user ID";
    }
    if (!point_is_valid(p_self) || !point_is_valid(p_peer) || !point_is_valid(r_self)) {
        return "Public key is not a valid point";
    }
    return NULL;
}

SM2KeySwapParams sm2_get_sb(int byte_len, ECPoint pA, ECPoint rA, ECPoint pB, const BigInt256 *dB,
                            ECPoint rB, const BigInt256 *rb, const char *idA, const char *idB) {
    SM2KeySwapParams result;
    BigInt256 x2_, tb, x1_;
    ECPoint v;
    uint8_t kb[SM2_MAX_KX_BYTES];
    uint8_t sb[32];
    const char *error;

    memset(&result, 0, sizeof(result));

    error = key_swap_input_error(byte_len, &pB, &rB, &pA, dB, rb, idA, idB);
    if (error != NULL) {
        strcpy(result.message, error);
        return result;
    }
    if (!point_is_valid(&rA)) {
        strcpy(result.message, "RA point is not on curve");
        return result;
    }

    x2_ = calc_x(&rB.x.value);
    tb = calc_t(rb, dB, &x2_);
    x1_ = calc_x(&rA.x.value);
    v = calc_point(&tb, &x1_, &pA, &rA);
    smx_wipe(&tb, sizeof(tb));
    if (v.infinity) {
        strcpy(result.message, "V is point at infinity");
        return result;
    }

    user_sm3_z(idA, &pA, result.za);
    user_sm3_z(idB, &pB, result.zb);

    kdf_key_swap(byte_len, &v, result.za, result.zb, kb);
    create_s(0x02, &v, result.za, result.zb, &rA, &rB, sb);

    bytes_to_hex(sb, 32, result.sb);
    bytes_to_hex(kb, (size_t)byte_len, result.kb);
    smx_wipe(kb, sizeof(kb));

    result.v = v;
    smx_wipe(&v, sizeof(v));
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
    uint8_t ka[SM2_MAX_KX_BYTES];
    const char *error;
    int match;

    memset(&result, 0, sizeof(result));

    error = key_swap_input_error(byte_len, &pA, &rA, &pB, dA, ra, idA, idB);
    if (error != NULL) {
        strcpy(result.message, error);
        return result;
    }
    if (!point_is_valid(&rB)) {
        strcpy(result.message, "RB point is not on curve");
        return result;
    }
    if (sb == NULL || sb_len != 32) {
        strcpy(result.message, "B's verification value does not match");
        return result;
    }

    x1_ = calc_x(&rA.x.value);
    ta = calc_t(ra, dA, &x1_);
    x2_ = calc_x(&rB.x.value);
    u = calc_point(&ta, &x2_, &pB, &rB);
    smx_wipe(&ta, sizeof(ta));
    if (u.infinity) {
        strcpy(result.message, "U is point at infinity");
        return result;
    }

    user_sm3_z(idA, &pA, za);
    user_sm3_z(idB, &pB, zb);

    kdf_key_swap(byte_len, &u, za, zb, ka);

    create_s(0x02, &u, za, zb, &rA, &rB, s1);
    match = bytes_equal(s1, sb, 32);
    SMX_DECLASSIFY(&match, sizeof(match));
    if (!match) {
        smx_wipe(ka, sizeof(ka));
        smx_wipe(&u, sizeof(u));
        strcpy(result.message, "B's verification value does not match");
        return result;
    }

    create_s(0x03, &u, za, zb, &rA, &rB, sa);
    smx_wipe(&u, sizeof(u));

    bytes_to_hex(sa, 32, result.sa);
    bytes_to_hex(ka, (size_t)byte_len, result.ka);
    smx_wipe(ka, sizeof(ka));

    result.success = 1;
    return result;
}

int sm2_check_sa(ECPoint v, const uint8_t *za, const uint8_t *zb, ECPoint rA, ECPoint rB,
                 const uint8_t *sa, size_t sa_len) {
    uint8_t s2[32];
    int match;
    if (za == NULL || zb == NULL || sa == NULL || sa_len != 32 || !point_is_valid(&v) ||
        !point_is_valid(&rA) || !point_is_valid(&rB)) {
        return 0;
    }
    create_s(0x03, &v, za, zb, &rA, &rB, s2);
    match = bytes_equal(s2, sa, 32);
    smx_wipe(s2, sizeof(s2));
    return match;
}
