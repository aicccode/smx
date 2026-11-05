/*
 * SM2 internals: randomness, key parsing, user ID hash (Z), KDF and constant-time compare.
 *
 * Part of the sm2.c translation unit, which includes it once: keeping one unit lets the
 * field arithmetic inline without LTO and exports no extra symbols.
 */

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
        accept = (int)(!bigint256_is_zero(out)) & (int)(smx_compare(out->limbs, max->limbs) <= 0);
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
    in_range &= smx_ct_barrier((uint64_t)0 - b);
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
    smx_mod_add(result.limbs, d->limbs, xr.limbs, SM2_N.limbs);
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
