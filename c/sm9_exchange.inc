/*
 * SM9 key exchange (GB/T 38635.3): sm9_exchange_init, _respond, _confirm and _check.
 *
 * Part of the sm9.c translation unit, which includes it once.
 */

static int sm9_exchange_init_core(const char *peer_id, const char *ppub_hex, int hid,
                                  const uint64_t *fixed_r, char r_hex[SM9_SCALAR_HEX_SIZE],
                                  char big_r_hex[SM9_G1_HEX_SIZE]) {
    g1_t ppub, q, big_r;
    uint64_t r[4];
    if (r_hex == NULL || big_r_hex == NULL) {
        return 0;
    }
    r_hex[0] = '\0';
    big_r_hex[0] = '\0';
    if (peer_id == NULL || !sm9_hid_ok(hid) || !sm9_parse_g1(ppub_hex, &ppub, 0) ||
        !sm9_user_point(&q, peer_id, hid, &ppub)) {
        return 0;
    }
    if (fixed_r != NULL) {
        memcpy(r, fixed_r, sizeof(r));
    } else if (!sm9_random_scalar(r)) {
        return 0;
    }
    g1_mul_ct(&big_r, &q, r);
    (void)g1_normalize(&big_r);
    SMX_DECLASSIFY(&big_r, sizeof(big_r)); /* sent to the peer */
    sm9_scalar_to_hex(r, r_hex);
    sm9_g1_to_hex(&big_r, big_r_hex);
    smx_wipe(r, sizeof(r));
    return 1;
}

int sm9_exchange_init(const char *peer_id, const char *master_public_hex, int hid,
                      char r_hex[SM9_SCALAR_HEX_SIZE], char R_hex[SM9_G1_HEX_SIZE]) {
    return sm9_exchange_init_core(peer_id, master_public_hex, hid, NULL, r_hex, R_hex);
}

/* Everything both sides parse, and the three GT values each computes. */
typedef struct {
    g1_t ra, rb;
    uint8_t g[3][384];
} sm9_exchange_state;

static void sm9_exchange_fail(SM9ExchangeResult *res, const char *message) {
    memset(res, 0, sizeof(*res));
    strcpy(res->message, message);
}

/*
 * Parses the inputs and computes g1, g2, g3. B (responder): g1 = e(R_A, de_B),
 * g2 = e(Ppub-e, P2)^r_B, g3 = g1^r_B. A: g1 = e(Ppub-e, P2)^r_A, g2 = e(R_B, de_A),
 * g3 = g2^r_A. Returns an error message, or NULL.
 */
static const char *sm9_exchange_compute(sm9_exchange_state *st, int responder, size_t key_len,
                                        const char *id_a, const char *id_b, const char *ppub_hex,
                                        const char *de_hex, const char *r_hex, const char *ra_hex,
                                        const char *rb_hex) {
    g1_t ppub;
    g2_t de;
    fq12_t peer, t;
    uint64_t r[4];

    if (key_len < 1 || key_len > SM9_MAX_EXCHANGE_KEY_BYTES) {
        return "Key length out of range";
    }
    if (id_a == NULL || id_b == NULL) {
        return "Invalid user ID";
    }
    if (!sm9_parse_g1(ppub_hex, &ppub, 0)) {
        return "Invalid master public key";
    }
    if (!sm9_parse_g1(ra_hex, &st->ra, 0)) {
        return "R_A is not a valid point";
    }
    if (!sm9_parse_g1(rb_hex, &st->rb, 0)) {
        return "R_B is not a valid point";
    }
    if (!sm9_parse_scalar(r_hex, r)) {
        return "Random value out of range";
    }
    if (!sm9_parse_g2(de_hex, &de)) {
        smx_wipe(r, sizeof(r));
        return "Invalid user private key";
    }
    sm9_pair_pow(&t, &ppub, r, &SM9_P2); /* e(Ppub-e, P2)^r */
    sm9_pair(&peer, responder ? &st->ra : &st->rb, &de);
    fq12_to_bytes(st->g[responder ? 1 : 0], &t);
    fq12_to_bytes(st->g[responder ? 0 : 1], &peer);
    sm9_gt_pow(&t, &peer, r);
    fq12_to_bytes(st->g[2], &t);
    smx_wipe(r, sizeof(r));
    smx_wipe(&de, sizeof(de));
    smx_wipe(&peer, sizeof(peer));
    smx_wipe(&t, sizeof(t));
    return NULL;
}

/* ID_A || ID_B || R_A.xy || R_B.xy */
static void sm9_exchange_tail(SM3 *ctx, const sm9_exchange_state *st, const char *id_a,
                              const char *id_b) {
    uint8_t xy[64];
    sm3_update(ctx, (const uint8_t *)id_a, strlen(id_a));
    sm3_update(ctx, (const uint8_t *)id_b, strlen(id_b));
    g1_affine_to_bytes(xy, &st->ra.x, &st->ra.y);
    sm3_update(ctx, xy, 64);
    g1_affine_to_bytes(xy, &st->rb.x, &st->rb.y);
    sm3_update(ctx, xy, 64);
}

/*
 * S_82 = SM3(0x82 || g1 || inner) and S_83 = SM3(0x83 || g1 || inner),
 * with inner = SM3(g2 || g3 || tail)
 */
static void sm9_exchange_confirmations(const sm9_exchange_state *st, const char *id_a,
                                       const char *id_b, uint8_t s82[32], uint8_t s83[32]) {
    uint8_t inner[32], tag;
    SM3 ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, st->g[1], 384);
    sm3_update(&ctx, st->g[2], 384);
    sm9_exchange_tail(&ctx, st, id_a, id_b);
    smx_sm3_finish_bytes(&ctx, inner);
    tag = 0x82;
    sm3_update(&ctx, &tag, 1);
    sm3_update(&ctx, st->g[0], 384);
    sm3_update(&ctx, inner, 32);
    smx_sm3_finish_bytes(&ctx, s82);
    tag = 0x83;
    sm3_update(&ctx, &tag, 1);
    sm3_update(&ctx, st->g[0], 384);
    sm3_update(&ctx, inner, 32);
    smx_sm3_finish_bytes(&ctx, s83);
    smx_wipe(inner, sizeof(inner));
    smx_wipe(&ctx, sizeof(ctx));
}

/* SK = KDF(tail || g1 || g2 || g3, key_len), as malloc'd hex; NULL if out of memory */
static char *sm9_exchange_key(const sm9_exchange_state *st, const char *id_a, const char *id_b,
                              size_t key_len) {
    sm9_kdf kdf;
    uint8_t block[32];
    char *hex = (char *)malloc(2 * key_len + 1);
    size_t off;
    if (hex == NULL) {
        return NULL;
    }
    sm3_init(&kdf.base);
    sm9_exchange_tail(&kdf.base, st, id_a, id_b);
    sm3_update(&kdf.base, st->g[0], 384);
    sm3_update(&kdf.base, st->g[1], 384);
    sm3_update(&kdf.base, st->g[2], 384);
    sm9_kdf_start(&kdf);
    for (off = 0; off < key_len; off += 32) {
        size_t n = key_len - off < 32 ? key_len - off : 32;
        sm9_kdf_read(&kdf, block, n);
        smx_hex_encode(block, n, hex + 2 * off, 'a');
    }
    hex[2 * key_len] = '\0';
    smx_wipe(block, sizeof(block));
    smx_wipe(&kdf, sizeof(kdf));
    return hex;
}

static SM9ExchangeResult sm9_exchange_finish(int responder, size_t key_len, const char *id_a,
                                             const char *id_b, const char *ppub_hex,
                                             const char *de_hex, const char *r_hex,
                                             const char *ra_hex, const char *rb_hex,
                                             const char *s_b_hex) {
    SM9ExchangeResult res;
    sm9_exchange_state st;
    uint8_t s82[32], s83[32], peer_sb[32];
    const char *error;

    sm9_exchange_fail(&res, "");
    if (!responder && !sm9_parse_hash(s_b_hex, peer_sb)) {
        sm9_exchange_fail(&res, "Invalid S_B");
        return res;
    }
    error = sm9_exchange_compute(&st, responder, key_len, id_a, id_b, ppub_hex, de_hex, r_hex,
                                 ra_hex, rb_hex);
    if (error != NULL) {
        sm9_exchange_fail(&res, error);
        smx_wipe(&st, sizeof(st));
        return res;
    }
    sm9_exchange_confirmations(&st, id_a, id_b, s82, s83);
    if (!responder) {
        int match = bytes_equal(s82, peer_sb, 32);
        SMX_DECLASSIFY(&match, sizeof(match));
        if (!match) {
            sm9_exchange_fail(&res, "S_B does not match");
            goto done;
        }
    }
    res.shared_key = sm9_exchange_key(&st, id_a, id_b, key_len);
    if (res.shared_key == NULL) {
        sm9_exchange_fail(&res, "Out of memory");
        goto done;
    }
    if (responder) {
        smx_hex_encode(s82, 32, res.s_b, 'a');
        res.s_b[64] = '\0';
        smx_hex_encode(s83, 32, res.s_2, 'a');
        res.s_2[64] = '\0';
    } else {
        smx_hex_encode(s83, 32, res.s_a, 'a');
        res.s_a[64] = '\0';
    }
    res.success = 1;
done:
    smx_wipe(&st, sizeof(st));
    smx_wipe(s82, sizeof(s82));
    smx_wipe(s83, sizeof(s83));
    return res;
}

SM9ExchangeResult sm9_exchange_respond(size_t key_len, const char *id_a, const char *id_b,
                                       const char *master_public_hex,
                                       const char *user_private_b_hex, const char *r_b_hex,
                                       const char *R_b_hex, const char *R_a_hex) {
    return sm9_exchange_finish(1, key_len, id_a, id_b, master_public_hex, user_private_b_hex,
                               r_b_hex, R_a_hex, R_b_hex, NULL);
}

SM9ExchangeResult sm9_exchange_confirm(size_t key_len, const char *id_a, const char *id_b,
                                       const char *master_public_hex,
                                       const char *user_private_a_hex, const char *r_a_hex,
                                       const char *R_a_hex, const char *R_b_hex,
                                       const char *s_b_hex) {
    return sm9_exchange_finish(0, key_len, id_a, id_b, master_public_hex, user_private_a_hex,
                               r_a_hex, R_a_hex, R_b_hex, s_b_hex);
}

int sm9_exchange_check(const char *s_2_hex, const char *s_a_hex) {
    uint8_t a[32], b[32];
    int match;
    if (!sm9_parse_hash(s_2_hex, a) || !sm9_parse_hash(s_a_hex, b)) {
        return 0;
    }
    match = bytes_equal(a, b, 32);
    smx_wipe(a, sizeof(a));
    smx_wipe(b, sizeof(b));
    SMX_DECLASSIFY(&match, sizeof(match));
    return match;
}

void sm9_exchange_result_free(SM9ExchangeResult *result) {
    if (result == NULL) {
        return;
    }
    if (result->shared_key != NULL) {
        smx_wipe(result->shared_key, strlen(result->shared_key));
        free(result->shared_key);
    }
    smx_wipe(result, sizeof(*result));
}
