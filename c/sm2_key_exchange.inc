/*
 * SM2 key exchange: the public sm2_get_sb, sm2_get_sa and sm2_check_sa.
 *
 * Part of the sm2.c translation unit, which includes it once: keeping one unit lets the
 * field arithmetic inline without LTO and exports no extra symbols.
 */

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
