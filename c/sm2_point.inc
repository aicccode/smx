/*
 * SM2 curve constants, and the public FpElement and ECPoint functions.
 *
 * Part of the sm2.c translation unit, which includes it once: keeping one unit lets the
 * field arithmetic inline without LTO and exports no extra symbols.
 */

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
