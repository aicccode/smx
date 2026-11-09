/*
 * SM9 identity-based cryptography (GB/T 38635): key generation, signatures, key encapsulation
 * and encryption here, key exchange in sm9_exchange.inc. The arithmetic is in sm9_fp.h,
 * sm9_tower.h, sm9_curve.h and sm9_pairing.h; see testvectors/SM9-SPEC.md for the encodings.
 *
 * Each operation that draws a random r has a static *_core variant taking an optional fixed r,
 * used by test_sm9.c (which includes this file) to reproduce the known-answer vectors.
 */
#include "sm9_pairing.h"
#include "sm2_support_ct.h"
#include "smx_internal.h"
#include <stdlib.h>
#include <string.h>

#include "sm9_support.inc"

/* ========== keys ========== */

static void sm9_g2_mul_hex(const uint64_t k[4], char out[SM9_G2_HEX_SIZE]) {
    g2_t p;
    g2_mul_ct(&p, &SM9_P2, k);
    (void)g2_normalize(&p);
    sm9_g2_to_hex(&p, out);
    smx_wipe(&p, sizeof(p));
}

static void sm9_g1_mul_hex(const uint64_t k[4], char out[SM9_G1_HEX_SIZE]) {
    g1_t p;
    g1_mul_ct(&p, &SM9_P1, k);
    (void)g1_normalize(&p);
    sm9_g1_to_hex(&p, out);
    smx_wipe(&p, sizeof(p));
}

/* type 0: signing, master public in G2; type 1: encryption, master public in G1 */
static int sm9_gen_master(int type, char pri[SM9_SCALAR_HEX_SIZE], char *pub) {
    uint64_t k[4];
    if (pri == NULL || pub == NULL) {
        return 0;
    }
    pri[0] = '\0';
    pub[0] = '\0';
    if (!sm9_random_scalar(k)) {
        return 0;
    }
    sm9_scalar_to_hex(k, pri);
    if (type == 0) {
        sm9_g2_mul_hex(k, pub);
    } else {
        sm9_g1_mul_hex(k, pub);
    }
    smx_wipe(k, sizeof(k));
    return 1;
}

static int sm9_master_public(int type, const char *pri, char *pub) {
    uint64_t k[4];
    if (pub == NULL) {
        return 0;
    }
    pub[0] = '\0';
    if (!sm9_parse_scalar(pri, k)) {
        return 0;
    }
    if (type == 0) {
        sm9_g2_mul_hex(k, pub);
    } else {
        sm9_g1_mul_hex(k, pub);
    }
    smx_wipe(k, sizeof(k));
    return 1;
}

int sm9_gen_sign_master_key(char master_private_hex[SM9_SCALAR_HEX_SIZE],
                            char master_public_hex[SM9_G2_HEX_SIZE]) {
    return sm9_gen_master(0, master_private_hex, master_public_hex);
}

int sm9_sign_master_public_key(const char *master_private_hex,
                               char master_public_hex[SM9_G2_HEX_SIZE]) {
    return sm9_master_public(0, master_private_hex, master_public_hex);
}

int sm9_gen_enc_master_key(char master_private_hex[SM9_SCALAR_HEX_SIZE],
                           char master_public_hex[SM9_G1_HEX_SIZE]) {
    return sm9_gen_master(1, master_private_hex, master_public_hex);
}

int sm9_enc_master_public_key(const char *master_private_hex,
                              char master_public_hex[SM9_G1_HEX_SIZE]) {
    return sm9_master_public(1, master_private_hex, master_public_hex);
}

/* t2 = k / (H1(ID || hid) + k) mod N; 0 if the sum is 0 mod N */
static int sm9_user_scalar(uint64_t t2[4], const uint64_t k[4], const char *id, int hid) {
    uint64_t h[4], t1[4], inv[4], zero;
    sm9_h1(h, id, hid);
    smx_mod_add(t1, h, k, SM9_N);
    zero = smx_mask_is_zero(t1[0] | t1[1] | t1[2] | t1[3]);
    SMX_DECLASSIFY(&zero, sizeof(zero));
    if (zero) {
        return 0;
    }
    sm9n_inv(inv, t1);
    sm9n_mul(t2, k, inv);
    smx_wipe(t1, sizeof(t1));
    smx_wipe(inv, sizeof(inv));
    return 1;
}

static int sm9_gen_user(int type, const char *pri, const char *id, int hid, char *out) {
    uint64_t k[4], t2[4];
    int ok;
    if (out == NULL) {
        return 0;
    }
    out[0] = '\0';
    if (id == NULL || !sm9_hid_ok(hid) || !sm9_parse_scalar(pri, k)) {
        return 0;
    }
    ok = sm9_user_scalar(t2, k, id, hid);
    if (ok && type == 0) {
        sm9_g1_mul_hex(t2, out);
    } else if (ok) {
        sm9_g2_mul_hex(t2, out);
    }
    smx_wipe(k, sizeof(k));
    smx_wipe(t2, sizeof(t2));
    return ok;
}

int sm9_gen_sign_user_key(const char *master_private_hex, const char *user_id, int hid,
                          char user_private_hex[SM9_G1_HEX_SIZE]) {
    return sm9_gen_user(0, master_private_hex, user_id, hid, user_private_hex);
}

int sm9_gen_enc_user_key(const char *master_private_hex, const char *user_id, int hid,
                         char user_private_hex[SM9_G2_HEX_SIZE]) {
    return sm9_gen_user(1, master_private_hex, user_id, hid, user_private_hex);
}

/* ========== signatures ========== */

static int sm9_sign_core(const uint8_t *msg, size_t len, const char *ds_hex, const char *ppub_hex,
                         const uint64_t *fixed_r, char sig[SM9_SIGNATURE_HEX_SIZE]) {
    g1_t ds, s;
    g2_t ppub;
    uint64_t r[4], h[4], l[4];
    uint8_t w[384], hb[32];
    int attempt, ok = 0;

    if (sig == NULL) {
        return 0;
    }
    sig[0] = '\0';
    if ((msg == NULL && len != 0) || !sm9_parse_g2(ppub_hex, &ppub)) {
        return 0;
    }
    if (!sm9_parse_g1(ds_hex, &ds, 0)) {
        return 0;
    }
    for (attempt = 0; attempt < (fixed_r != NULL ? 1 : SM9_MAX_RETRIES); attempt++) {
        uint64_t zero;
        if (fixed_r != NULL) {
            memcpy(r, fixed_r, sizeof(r));
        } else if (!sm9_random_scalar(r)) {
            break;
        }
        sm9_pair_pow_bytes(w, &SM9_P1, r, &ppub); /* w = e(P1, Ppub-s)^r */
        sm9_h2(h, msg, len, w);
        SMX_DECLASSIFY(h, sizeof(h)); /* h is published */
        smx_mod_sub(l, r, h, SM9_N);
        zero = smx_mask_is_zero(l[0] | l[1] | l[2] | l[3]);
        SMX_DECLASSIFY(&zero, sizeof(zero));
        if (zero) {
            continue;
        }
        g1_mul_ct(&s, &ds, l);
        (void)g1_normalize(&s);
        SMX_DECLASSIFY(&s, sizeof(s));
        sm9_scalar_to_be(hb, h);
        smx_hex_encode(hb, 32, sig, 'a');
        sm9_g1_to_hex(&s, sig + 64);
        ok = 1;
        break;
    }
    smx_wipe(&ds, sizeof(ds));
    smx_wipe(r, sizeof(r));
    smx_wipe(l, sizeof(l));
    smx_wipe(w, sizeof(w));
    smx_wipe(&s, sizeof(s));
    return ok;
}

int sm9_sign_bytes(const uint8_t *message, size_t len, const char *user_private_hex,
                   const char *master_public_hex, char signature_hex[SM9_SIGNATURE_HEX_SIZE]) {
    return sm9_sign_core(message, len, user_private_hex, master_public_hex, NULL, signature_hex);
}

int sm9_sign(const char *message, const char *user_private_hex, const char *master_public_hex,
             char signature_hex[SM9_SIGNATURE_HEX_SIZE]) {
    if (message == NULL) {
        if (signature_hex != NULL) {
            signature_hex[0] = '\0';
        }
        return 0;
    }
    return sm9_sign_bytes((const uint8_t *)message, strlen(message), user_private_hex,
                          master_public_hex, signature_hex);
}

/*
 * Public data only, so variable time. g^h e(S, P) = e([h]P1, Ppub-s) e(S, P), two Miller loops
 * and one final exponentiation instead of two pairings and an exponentiation.
 */
int sm9_verify_bytes(const uint8_t *message, size_t len, const char *signature_hex,
                     const char *user_id, const char *master_public_hex, int hid) {
    uint8_t raw[97], w[384];
    uint64_t h[4], h1[4], h2[4];
    g1_t s, hp;
    g2_t ppub, p;
    fq12_t f, f2;

    if ((message == NULL && len != 0) || signature_hex == NULL || user_id == NULL ||
        !sm9_hid_ok(hid) || strlen(signature_hex) != 194) {
        return 0;
    }
    if (!smx_hex_decode_lower(signature_hex, 97, raw)) {
        return 0;
    }
    sm9_scalar_from_be(h, raw);
    if (!sm9n_in_range(h) || !g1_from_bytes(&s, raw + 32) ||
        !sm9_parse_g2(master_public_hex, &ppub)) {
        return 0;
    }

    g1_mul_vt(&hp, &SM9_P1, h);
    (void)g1_normalize(&hp);
    sm9_miller_loop(&f, &hp.x, &hp.y, &ppub.x, &ppub.y);
    sm9_h1(h1, user_id, hid);
    g2_mul_vt(&p, &SM9_P2, h1);
    g2_add_vt(&p, &p, &ppub);
    if (g2_normalize(&p)) {
        sm9_miller_loop(&f2, &s.x, &s.y, &p.x, &p.y);
        fq12_mul(&f, &f, &f2);
    } /* else e(S, O) = 1 */
    sm9_final_exp(&f, &f);
    fq12_to_bytes(w, &f);
    sm9_h2(h2, message, len, w);
    return memcmp(h2, h, sizeof(h)) == 0;
}

int sm9_verify(const char *message, const char *signature_hex, const char *user_id,
               const char *master_public_hex, int hid) {
    if (message == NULL) {
        return 0;
    }
    return sm9_verify_bytes((const uint8_t *)message, strlen(message), signature_hex, user_id,
                            master_public_hex, hid);
}

/* ========== encryption and KEM ========== */

/*
 * What encryption and encapsulation share: Ppub-e parsed and QB = [H1]P1 + Ppub-e. Returns 0
 * for an invalid key, or if QB is infinity.
 */
static int sm9_enc_setup(const char *ppub_hex, const char *id, int hid, g1_t *ppub, g1_t *qb) {
    return id != NULL && sm9_hid_ok(hid) && sm9_parse_g1(ppub_hex, ppub, 0) &&
           sm9_user_point(qb, id, hid, ppub);
}

/* C = [r]QB, normalized, and w = e(Ppub-e, P2)^r as bytes */
static void sm9_enc_point(g1_t *c, uint8_t w[384], const g1_t *qb, const g1_t *ppub,
                          const uint64_t r[4]) {
    g1_mul_ct(c, qb, r);
    (void)g1_normalize(c);
    SMX_DECLASSIFY(c, sizeof(*c)); /* published */
    sm9_pair_pow_bytes(w, ppub, r, &SM9_P2);
}

/* The parts of C2 and C3 that depend on the mode. Returns 0 if K1 was all zero. */
static int sm9_enc_body(sm9_kdf *kdf, const uint8_t *data, size_t len, int mode, uint8_t *c2,
                        size_t c2_len, uint8_t c3[32]) {
    uint8_t k1[32], k2[32];
    uint8_t any = 0;
    size_t off, i;
    SM3 mac;

    if (mode == SM9_MODE_STREAM) {
        for (off = 0; off < len; off += 32) {
            size_t n = len - off < 32 ? len - off : 32;
            sm9_kdf_read(kdf, k1, n);
            for (i = 0; i < n; i++) {
                any |= k1[i];
                c2[off + i] = (uint8_t)(data[off + i] ^ k1[i]);
            }
        }
    } else {
        sm9_kdf_read(kdf, k1, 16);
        for (i = 0; i < 16; i++) {
            any |= k1[i];
        }
        memcpy(c2, data, len);
        memset(c2 + len, (int)(c2_len - len), c2_len - len);
        smx_sm4_ecb_encrypt(k1, c2, c2, c2_len / 16);
    }
    sm9_kdf_read(kdf, k2, 32);
    smx_wipe(k1, sizeof(k1));
    SMX_DECLASSIFY(&any, sizeof(any));
    if (any == 0) {
        smx_wipe(k2, sizeof(k2));
        return 0;
    }
    sm3_init(&mac);
    sm3_update(&mac, c2, c2_len);
    sm3_update(&mac, k2, 32);
    smx_sm3_finish_bytes(&mac, c3);
    smx_wipe(k2, sizeof(k2));
    smx_wipe(&mac, sizeof(mac));
    return 1;
}

static char *sm9_encrypt_core(const uint8_t *data, size_t len, const char *id,
                              const char *ppub_hex, int hid, int mode, const uint64_t *fixed_r) {
    g1_t ppub, qb, c1;
    uint64_t r[4];
    uint8_t w[384], c3[32];
    uint8_t *c2;
    size_t c2_len;
    char *out = NULL;
    int attempt;

    if (data == NULL || len == 0 || (mode != SM9_MODE_STREAM && mode != SM9_MODE_SM4)) {
        return NULL;
    }
    if ((uint64_t)len > SM9_MAX_KDF_BYTES - 32 || len > (SIZE_MAX - 300) / 2 - 16) {
        return NULL;
    }
    c2_len = mode == SM9_MODE_STREAM ? len : (len / 16 + 1) * 16;
    if (!sm9_enc_setup(ppub_hex, id, hid, &ppub, &qb)) {
        return NULL;
    }
    c2 = (uint8_t *)malloc(c2_len);
    if (c2 == NULL) {
        return NULL;
    }
    for (attempt = 0; attempt < (fixed_r != NULL ? 1 : SM9_MAX_RETRIES); attempt++) {
        sm9_kdf kdf;
        int good;
        if (fixed_r != NULL) {
            memcpy(r, fixed_r, sizeof(r));
        } else if (!sm9_random_scalar(r)) {
            break;
        }
        sm9_enc_point(&c1, w, &qb, &ppub, r);
        sm9_kdf_init_enc(&kdf, &c1, w, id);
        good = sm9_enc_body(&kdf, data, len, mode, c2, c2_len, c3);
        smx_wipe(&kdf, sizeof(kdf));
        if (!good) {
            continue;
        }
        out = (char *)malloc(194 + 2 * c2_len + 1);
        if (out != NULL) {
            sm9_g1_to_hex(&c1, out);
            smx_hex_encode(c3, 32, out + 130, 'a');
            smx_hex_encode(c2, c2_len, out + 194, 'a');
            out[194 + 2 * c2_len] = '\0';
        }
        break;
    }
    smx_wipe(r, sizeof(r));
    smx_wipe(w, sizeof(w));
    smx_wipe(c2, c2_len);
    free(c2);
    return out;
}

char *sm9_encrypt_bytes(const uint8_t *data, size_t len, const char *user_id,
                        const char *master_public_hex, int hid, int mode) {
    return sm9_encrypt_core(data, len, user_id, master_public_hex, hid, mode, NULL);
}

char *sm9_encrypt(const char *plaintext, const char *user_id, const char *master_public_hex,
                  int hid, int mode) {
    if (plaintext == NULL) {
        return NULL;
    }
    return sm9_encrypt_bytes((const uint8_t *)plaintext, strlen(plaintext), user_id,
                             master_public_hex, hid, mode);
}

/* w = e(C, de) as bytes, for a user key in hex; 0 if the key is invalid */
static int sm9_dec_pairing(uint8_t w[384], const g1_t *c, const char *de_hex) {
    g2_t de;
    fq12_t e;
    if (!sm9_parse_g2(de_hex, &de)) {
        return 0;
    }
    sm9_pair(&e, c, &de);
    fq12_to_bytes(w, &e);
    smx_wipe(&de, sizeof(de));
    smx_wipe(&e, sizeof(e));
    return 1;
}

/*
 * Recomputes K, checks K1 and C3 (constant time), and only then decrypts c2 in place. Returns 1
 * and the plaintext length, or 0 on any failure.
 */
static int sm9_dec_body(sm9_kdf *kdf, uint8_t *c2, size_t c2_len, const uint8_t c3[32], int mode,
                        uint8_t *k1, size_t *plain_len) {
    uint8_t k2[32], mac_out[32];
    uint8_t any = 0;
    size_t i;
    uint64_t ok;
    SM3 mac;

    *plain_len = c2_len;

    sm9_kdf_read(kdf, k1, mode == SM9_MODE_STREAM ? c2_len : 16);
    for (i = 0; i < (mode == SM9_MODE_STREAM ? c2_len : 16); i++) {
        any |= k1[i];
    }
    sm9_kdf_read(kdf, k2, 32);
    sm3_init(&mac);
    sm3_update(&mac, c2, c2_len);
    sm3_update(&mac, k2, 32);
    smx_sm3_finish_bytes(&mac, mac_out);
    ok = smx_mask_from_bit((uint64_t)bytes_equal(mac_out, c3, 32)) &
         ~smx_mask_is_zero((uint64_t)any);
    smx_wipe(k2, sizeof(k2));
    smx_wipe(mac_out, sizeof(mac_out));
    smx_wipe(&mac, sizeof(mac));
    SMX_DECLASSIFY(&ok, sizeof(ok));
    if (!ok) {
        return 0;
    }
    if (mode == SM9_MODE_STREAM) {
        for (i = 0; i < c2_len; i++) {
            c2[i] ^= k1[i];
        }
    } else {
        ok = smx_sm4_ecb_decrypt_pkcs7(k1, c2, c2_len, plain_len);
        SMX_DECLASSIFY(&ok, sizeof(ok));
        SMX_DECLASSIFY(plain_len, sizeof(*plain_len));
        if (!ok) {
            return 0; /* C3 already matched: one full padding block decrypts to empty bytes */
        }
    }
    return 1;
}

uint8_t *sm9_decrypt_bytes(const char *ciphertext_hex, const char *user_id,
                           const char *user_private_hex, int mode, size_t *out_len) {
    size_t hex_len, c2_len, plain_len = 0;
    uint8_t c3[32], w[384];
    uint8_t *c2 = NULL, *k1 = NULL;
    g1_t c1;
    int ok = 0;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (ciphertext_hex == NULL || user_id == NULL ||
        (mode != SM9_MODE_STREAM && mode != SM9_MODE_SM4)) {
        return NULL;
    }
    hex_len = strlen(ciphertext_hex);
    if (hex_len < 194 + 2 || (hex_len & 1) != 0) {
        return NULL;
    }
    c2_len = (hex_len - 194) / 2;
    if ((uint64_t)c2_len > SM9_MAX_KDF_BYTES - 32 ||
        (mode == SM9_MODE_SM4 && c2_len % 16 != 0)) {
        return NULL;
    }
    if (!sm9_decode_g1(ciphertext_hex, &c1, 1) ||
        !smx_hex_decode_lower(ciphertext_hex + 130, 32, c3)) {
        return NULL;
    }
    c2 = (uint8_t *)malloc(c2_len + 1);
    k1 = (uint8_t *)malloc(mode == SM9_MODE_STREAM ? c2_len : 16);
    if (c2 != NULL && k1 != NULL && smx_hex_decode_lower(ciphertext_hex + 194, c2_len, c2) &&
        sm9_dec_pairing(w, &c1, user_private_hex)) {
        sm9_kdf kdf;
        sm9_kdf_init_enc(&kdf, &c1, w, user_id);
        ok = sm9_dec_body(&kdf, c2, c2_len, c3, mode, k1, &plain_len);
        smx_wipe(&kdf, sizeof(kdf));
        smx_wipe(w, sizeof(w));
    }
    if (k1 != NULL) {
        smx_wipe(k1, mode == SM9_MODE_STREAM ? c2_len : 16);
        free(k1);
    }
    if (!ok) {
        if (c2 != NULL) {
            smx_wipe(c2, c2_len);
            free(c2);
        }
        return NULL;
    }
    c2[plain_len] = '\0';
    if (out_len != NULL) {
        *out_len = plain_len;
    }
    return c2;
}

char *sm9_decrypt(const char *ciphertext_hex, const char *user_id, const char *user_private_hex,
                  int mode) {
    return (char *)sm9_decrypt_bytes(ciphertext_hex, user_id, user_private_hex, mode, NULL);
}

/* the KEM key: KDF(C.xy || w || ID, klen) into key, hex into key_hex; 0 if it is all zero */
static int sm9_kem_key(const g1_t *c, const uint8_t w[384], const char *id, uint8_t *key,
                       size_t key_len, char *key_hex) {
    sm9_kdf kdf;
    uint8_t any = 0;
    size_t i;
    sm9_kdf_init_enc(&kdf, c, w, id);
    sm9_kdf_read(&kdf, key, key_len);
    smx_wipe(&kdf, sizeof(kdf));
    for (i = 0; i < key_len; i++) {
        any |= key[i];
    }
    SMX_DECLASSIFY(&any, sizeof(any));
    if (any == 0) {
        return 0;
    }
    smx_hex_encode(key, key_len, key_hex, 'a');
    key_hex[2 * key_len] = '\0';
    return 1;
}

static int sm9_kem_len_ok(size_t key_len) {
    return key_len >= 1 && key_len <= SM9_MAX_EXCHANGE_KEY_BYTES;
}

static int sm9_encapsulate_core(const char *id, const char *ppub_hex, size_t key_len, int hid,
                                const uint64_t *fixed_r, char *key_hex, char *c_hex) {
    g1_t ppub, qb, c;
    uint64_t r[4];
    uint8_t w[384];
    uint8_t *key;
    int attempt, ok = 0;

    if (key_hex == NULL || c_hex == NULL) {
        return 0;
    }
    key_hex[0] = '\0';
    c_hex[0] = '\0';
    if (!sm9_kem_len_ok(key_len) || !sm9_enc_setup(ppub_hex, id, hid, &ppub, &qb)) {
        return 0;
    }
    key = (uint8_t *)malloc(key_len);
    if (key == NULL) {
        return 0;
    }
    for (attempt = 0; attempt < (fixed_r != NULL ? 1 : SM9_MAX_RETRIES); attempt++) {
        if (fixed_r != NULL) {
            memcpy(r, fixed_r, sizeof(r));
        } else if (!sm9_random_scalar(r)) {
            break;
        }
        sm9_enc_point(&c, w, &qb, &ppub, r);
        if (sm9_kem_key(&c, w, id, key, key_len, key_hex)) {
            sm9_g1_to_hex(&c, c_hex);
            ok = 1;
            break;
        }
    }
    smx_wipe(r, sizeof(r));
    smx_wipe(w, sizeof(w));
    smx_wipe(key, key_len);
    free(key);
    return ok;
}

int sm9_encapsulate(const char *user_id, const char *master_public_hex, size_t key_len, int hid,
                    char *key_hex, char ciphertext_hex[SM9_G1_HEX_SIZE]) {
    return sm9_encapsulate_core(user_id, master_public_hex, key_len, hid, NULL, key_hex,
                                ciphertext_hex);
}

int sm9_decapsulate(const char *ciphertext_hex, const char *user_id, const char *user_private_hex,
                    size_t key_len, char *key_hex) {
    g1_t c;
    uint8_t w[384];
    uint8_t *key;
    int ok = 0;
    if (key_hex == NULL) {
        return 0;
    }
    key_hex[0] = '\0';
    if (user_id == NULL || !sm9_kem_len_ok(key_len) || !sm9_parse_g1(ciphertext_hex, &c, 1)) {
        return 0;
    }
    key = (uint8_t *)malloc(key_len);
    if (key == NULL) {
        return 0;
    }
    if (sm9_dec_pairing(w, &c, user_private_hex)) {
        ok = sm9_kem_key(&c, w, user_id, key, key_len, key_hex);
        smx_wipe(w, sizeof(w));
    }
    smx_wipe(key, key_len);
    free(key);
    return ok;
}

#include "sm9_exchange.inc"
