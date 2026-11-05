/* getrandom/getentropy and open() are not in strict C99 headers. */
#if !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE 1
#endif
#if !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#include "sm2_ec.h"
#include "sm2_support_ct.h"
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

#include "sm2_point.inc"
#include "sm2_support.inc"

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
    uint8_t c1_bytes[65], c3[32], computed[32], key[32], coord[32];
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
    /* one spelling per ciphertext: lowercase, as sm2_encrypt emits, all the way through */
    if (!smx_hex_decode_lower(ciphertext_hex, 65, c1_bytes)) {
        return NULL;
    }
    memcpy(c1_hex, ciphertext_hex, 130);
    c1_hex[130] = '\0';
    c1 = ec_point_from_hex_encoded(c1_hex);
    if (c1.infinity || !smx_hex_decode_lower(ciphertext_hex + 130, 32, c3)) {
        return NULL;
    }
    plain = (uint8_t *)malloc(c2_len + 1);
    if (plain == NULL) {
        return NULL;
    }
    if (!smx_hex_decode_lower(ciphertext_hex + 194, c2_len, plain) ||
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
        smx_mod_add(r.limbs, e.limbs, x1.limbs, SM2_N.limbs);
        carry = bigint256_add(&rk, &r, &k);
        /* r + k involves the nonce: no short-circuit, so no branch on its carry */
        reject =
            bigint256_is_zero(&r) | ((int)(carry ^ 1) & (smx_compare(rk.limbs, SM2_N.limbs) == 0));
        smx_wipe(&rk, sizeof(rk));
        SMX_DECLASSIFY(&reject, sizeof(reject));
        if (reject) {
            continue;
        }

        fn_mul(rd.limbs, r.limbs, d.limbs);
        smx_mod_sub(k_minus_rd.limbs, k.limbs, rd.limbs, SM2_N.limbs);
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

/* Exactly 64 lowercase hex digits: one signature must have one spelling. */
static int parse_signature_scalar(const char *hex, BigInt256 *out) {
    uint8_t be[32];
    if (!smx_hex_decode_lower(hex, 32, be)) {
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

#include "sm2_key_exchange.inc"
