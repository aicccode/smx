/*
 * SM9 internals: randomness, parsing and encoding, H1/H2, the KDF and the pairing wrapper.
 *
 * Part of the sm9.c translation unit, which includes it once: keeping one unit lets the
 * field arithmetic inline without LTO and exports no extra symbols.
 */

/* Upper limit on rejected draws. A correct RNG fails 256 in a row with chance below 2^-400. */
#define SM9_MAX_RETRIES 256
/* A KDF counter of 32 bits gives at most this many output bytes */
#define SM9_MAX_KDF_BYTES (((uint64_t)0xFFFFFFFFu) * 32)

/* A uniform scalar in [1, N-1] by rejection sampling; 0 if the RNG failed. */
static int sm9_random_scalar(uint64_t k[4]) {
    int attempt;
    for (attempt = 0; attempt < SM9_MAX_RETRIES; attempt++) {
        uint8_t b[32];
        uint64_t accept;
        int i;
        if (!smx_random_bytes(b, sizeof(b))) {
            smx_wipe(b, sizeof(b));
            return 0;
        }
        for (i = 0; i < 4; i++) {
            k[i] = smx_load_be64(b + 24 - 8 * i);
        }
        smx_wipe(b, sizeof(b));
        /* a rejected draw reveals nothing about the value finally accepted */
        accept = sm9n_in_range(k);
        SMX_DECLASSIFY(&accept, sizeof(accept));
        if (accept) {
            return 1;
        }
    }
    smx_wipe(k, 32);
    return 0;
}

static int sm9_hid_ok(int hid) {
    return hid >= 0 && hid <= 255;
}

static void sm9_scalar_from_be(uint64_t k[4], const uint8_t be[32]) {
    int i;
    for (i = 0; i < 4; i++) {
        k[i] = smx_load_be64(be + 24 - 8 * i);
    }
}

static void sm9_scalar_to_be(uint8_t be[32], const uint64_t k[4]) {
    int i;
    for (i = 0; i < 4; i++) {
        smx_store_be64(be + 24 - 8 * i, k[i]);
    }
}

/* Exactly 64 hex digits of either case, in [1, N-1]. Only validity can show in the timing. */
static int sm9_parse_scalar(const char *hex, uint64_t k[4]) {
    uint8_t be[32];
    uint64_t ok;
    if (hex == NULL || strlen(hex) != 64) {
        return 0;
    }
    ok = smx_mask_from_bit((uint64_t)smx_hex_decode(hex, 32, be));
    sm9_scalar_from_be(k, be);
    smx_wipe(be, sizeof(be));
    ok &= sm9n_in_range(k);
    SMX_DECLASSIFY(&ok, sizeof(ok));
    if (!ok) {
        smx_wipe(k, 32);
        return 0;
    }
    return 1;
}

/* A G1 point from exactly 130 hex digits at hex; lowercase only for ciphertexts and signatures. */
static int sm9_decode_g1(const char *hex, g1_t *p, int lower_only) {
    uint8_t raw[65];
    uint64_t ok;
    ok = smx_mask_from_bit(
        (uint64_t)(lower_only ? smx_hex_decode_lower(hex, 65, raw) : smx_hex_decode(hex, 65, raw)));
    ok &= g1_from_bytes(p, raw);
    smx_wipe(raw, sizeof(raw));
    SMX_DECLASSIFY(&ok, sizeof(ok));
    if (!ok) {
        smx_wipe(p, sizeof(*p));
        return 0;
    }
    return 1;
}

static int sm9_parse_g1(const char *hex, g1_t *p, int lower_only) {
    return hex != NULL && strlen(hex) == 130 && sm9_decode_g1(hex, p, lower_only);
}

/* A G2 point, 258 hex digits of either case, in the subgroup. */
static int sm9_parse_g2(const char *hex, g2_t *p) {
    uint8_t raw[129];
    int ok;
    if (hex == NULL || strlen(hex) != 258) {
        return 0;
    }
    ok = smx_hex_decode(hex, 129, raw);
    SMX_DECLASSIFY(&ok, sizeof(ok));
    ok = ok && g2_from_bytes(p, raw) != 0;
    smx_wipe(raw, sizeof(raw));
    if (!ok) {
        smx_wipe(p, sizeof(*p));
        return 0;
    }
    return 1;
}

/* 32 bytes, 64 lowercase hex digits (confirmation values, like signatures) */
static int sm9_parse_hash(const char *hex, uint8_t out[32]) {
    return hex != NULL && strlen(hex) == 64 && smx_hex_decode_lower(hex, 32, out);
}

/* Affine form with Z = 1. Returns all ones unless p is infinity. */
static uint64_t g1_normalize(g1_t *p) {
    uint64_t finite = ~fq_is_zero(&p->z);
    g1_to_affine(&p->x, &p->y, p);
    p->z = FQ_ONE;
    return finite;
}

static uint64_t g2_normalize(g2_t *p) {
    uint64_t finite = ~fq2_is_zero(&p->z);
    g2_to_affine(&p->x, &p->y, p);
    fq2_set_one(&p->z);
    return finite;
}

/* lowercase hex of a normalized point */
static void sm9_g1_to_hex(const g1_t *p, char out[SM9_G1_HEX_SIZE]) {
    uint8_t raw[65];
    raw[0] = 0x04;
    g1_affine_to_bytes(raw + 1, &p->x, &p->y);
    smx_hex_encode(raw, 65, out, 'a');
    out[130] = '\0';
    smx_wipe(raw, sizeof(raw));
}

static void sm9_g2_to_hex(const g2_t *p, char out[SM9_G2_HEX_SIZE]) {
    uint8_t raw[129];
    raw[0] = 0x04;
    g2_affine_to_bytes(raw + 1, &p->x, &p->y);
    smx_hex_encode(raw, 129, out, 'a');
    out[258] = '\0';
    smx_wipe(raw, sizeof(raw));
}

static void sm9_scalar_to_hex(const uint64_t k[4], char out[SM9_SCALAR_HEX_SIZE]) {
    uint8_t be[32];
    sm9_scalar_to_be(be, k);
    smx_hex_encode(be, 32, out, 'a');
    out[64] = '\0';
    smx_wipe(be, sizeof(be));
}

/*
 * H(tag, Z) of GB/T 38635.2, for a context that has absorbed tag || Z:
 * Ha = SM3(.. || 00000001) || SM3(.. || 00000002)[0..8), h = (Ha mod (N - 1)) + 1.
 * The reduction shifts the 320 bits in one at a time, subtracting N - 1 whenever it fits.
 */
static void sm9_hash_to_range(uint64_t h[4], const SM3 *absorbed) {
    static const uint8_t ct1[4] = {0, 0, 0, 1}, ct2[4] = {0, 0, 0, 2};
    uint8_t ha[64];
    SM3 ctx;
    uint64_t r[4] = {0, 0, 0, 0}, c;
    int i, bit;

    ctx = *absorbed;
    sm3_update(&ctx, ct1, 4);
    smx_sm3_finish_bytes(&ctx, ha);
    ctx = *absorbed;
    sm3_update(&ctx, ct2, 4);
    smx_sm3_finish_bytes(&ctx, ha + 32);
    for (i = 0; i < 40; i++) {
        for (bit = 7; bit >= 0; bit--) {
            uint64_t top = r[3] >> 63;
            r[3] = (r[3] << 1) | (r[2] >> 63);
            r[2] = (r[2] << 1) | (r[1] >> 63);
            r[1] = (r[1] << 1) | (r[0] >> 63);
            r[0] = (r[0] << 1) | ((uint64_t)(ha[i] >> bit) & 1);
            sm9_reduce_once(r, r, top, SM9_N_MINUS_1);
        }
    }
    h[0] = smx_addc(r[0], 1, 0, &c);
    h[1] = smx_addc(r[1], 0, c, &c);
    h[2] = smx_addc(r[2], 0, c, &c);
    h[3] = smx_addc(r[3], 0, c, &c);
    smx_wipe(&ctx, sizeof(ctx));
    smx_wipe(ha, sizeof(ha));
    smx_wipe(r, sizeof(r));
}

/* H1(ID || hid) */
static void sm9_h1(uint64_t h[4], const char *id, int hid) {
    uint8_t tag = 0x01, hid_byte = (uint8_t)hid;
    SM3 ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, &tag, 1);
    sm3_update(&ctx, (const uint8_t *)id, strlen(id));
    sm3_update(&ctx, &hid_byte, 1);
    sm9_hash_to_range(h, &ctx);
}

/* H2(M || w) */
static void sm9_h2(uint64_t h[4], const uint8_t *msg, size_t len, const uint8_t w[384]) {
    uint8_t tag = 0x02;
    SM3 ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, &tag, 1);
    sm3_update(&ctx, msg, len);
    sm3_update(&ctx, w, 384);
    sm9_hash_to_range(h, &ctx);
    smx_wipe(&ctx, sizeof(ctx));
}

/* KDF(Z, klen) = SM3(Z || 1) || SM3(Z || 2) || ..., read in pieces of any size */
typedef struct {
    SM3 base; /* has absorbed Z */
    uint32_t ct;
    uint8_t block[32];
    size_t pos;
} sm9_kdf;

static void sm9_kdf_start(sm9_kdf *k) {
    k->ct = 1;
    k->pos = 32;
}

static void sm9_kdf_read(sm9_kdf *k, uint8_t *out, size_t n) {
    while (n > 0) {
        size_t take;
        if (k->pos == 32) {
            uint8_t ct[4];
            SM3 ctx = k->base;
            smx_store_be32(ct, k->ct++);
            sm3_update(&ctx, ct, 4);
            smx_sm3_finish_bytes(&ctx, k->block);
            smx_wipe(&ctx, sizeof(ctx));
            k->pos = 0;
        }
        take = 32 - k->pos < n ? 32 - k->pos : n;
        memcpy(out, k->block + k->pos, take);
        k->pos += take;
        out += take;
        n -= take;
    }
}

/* SM3(Z || ct) for the KEM and encryption: Z = C.xy || w || ID */
static void sm9_kdf_init_enc(sm9_kdf *k, const g1_t *c, const uint8_t w[384], const char *id) {
    uint8_t xy[64];
    g1_affine_to_bytes(xy, &c->x, &c->y);
    sm3_init(&k->base);
    sm3_update(&k->base, xy, 64);
    sm3_update(&k->base, w, 384);
    sm3_update(&k->base, (const uint8_t *)id, strlen(id));
    sm9_kdf_start(k);
}

/* e(P, Q) for normalized points, neither infinity */
static void sm9_pair(fq12_t *r, const g1_t *p, const g2_t *q) {
    sm9_pairing(r, &p->x, &p->y, &q->x, &q->y);
}

/*
 * e(P, Q)^k = e([k]P, Q), for a secret k in [1, N-1]: a constant-time G1 multiplication costs
 * far less than an exponentiation in GT. [k]P is never infinity, P having order N.
 */
static void sm9_pair_pow(fq12_t *r, const g1_t *p, const uint64_t k[4], const g2_t *q) {
    g1_t kp;
    g1_mul_ct(&kp, p, k);
    (void)g1_normalize(&kp);
    sm9_pair(r, &kp, q);
    smx_wipe(&kp, sizeof(kp));
}

static void sm9_pair_pow_bytes(uint8_t out[384], const g1_t *p, const uint64_t k[4],
                               const g2_t *q) {
    fq12_t w;
    sm9_pair_pow(&w, p, k, q);
    fq12_to_bytes(out, &w);
    smx_wipe(&w, sizeof(w));
}

/* QB = [H1(ID || hid)]P1 + Ppub-e, normalized; 0 if it is infinity */
static int sm9_user_point(g1_t *qb, const char *id, int hid, const g1_t *ppub) {
    uint64_t h[4];
    uint64_t finite;
    sm9_h1(h, id, hid);
    g1_mul_vt(qb, &SM9_P1, h);
    g1_add_vt(qb, qb, ppub);
    finite = g1_normalize(qb);
    return finite != 0;
}
