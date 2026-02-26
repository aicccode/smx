#ifndef SMX_H
#define SMX_H

#include <stdint.h>
#include <stddef.h>

/* ========== BigInt256: 256-bit unsigned integer, 4 x uint64 limbs, little-endian ========== */

typedef struct { uint64_t limbs[4]; } BigInt256;

BigInt256 bigint256_zero(void);
BigInt256 bigint256_one(void);
BigInt256 bigint256_from_hex(const char *hex);
BigInt256 bigint256_from_be_bytes(const uint8_t *data, size_t len);
void bigint256_to_be_bytes(const BigInt256 *a, uint8_t out[32]);
void bigint256_to_hex(const BigInt256 *a, char out[65]);
void bigint256_to_hex_lower(const BigInt256 *a, char out[65]);
int bigint256_is_zero(const BigInt256 *a);
int bigint256_is_one(const BigInt256 *a);
int bigint256_compare(const BigInt256 *a, const BigInt256 *b);
uint64_t bigint256_add(BigInt256 *r, const BigInt256 *a, const BigInt256 *b);
uint64_t bigint256_sub(BigInt256 *r, const BigInt256 *a, const BigInt256 *b);
void bigint256_mul(uint64_t r[8], const BigInt256 *a, const BigInt256 *b);
void bigint256_mod_add(BigInt256 *r, const BigInt256 *a, const BigInt256 *b, const BigInt256 *m);
void bigint256_mod_sub(BigInt256 *r, const BigInt256 *a, const BigInt256 *b, const BigInt256 *m);
void bigint256_mod_mul(BigInt256 *r, const BigInt256 *a, const BigInt256 *b, const BigInt256 *m);
void bigint256_mod_inverse(BigInt256 *r, const BigInt256 *a, const BigInt256 *m);
void bigint256_mod_pow(BigInt256 *r, const BigInt256 *base, const BigInt256 *exp, const BigInt256 *m);
void bigint256_sm2_mod_mul_p(BigInt256 *r, const BigInt256 *a, const BigInt256 *b);
void bigint256_sm2_mod_square_p(BigInt256 *r, const BigInt256 *a);
int bigint256_get_bit(const BigInt256 *a, int i);
int bigint256_bit_length(const BigInt256 *a);
void bigint256_and(BigInt256 *r, const BigInt256 *a, const BigInt256 *b);

/* ========== SM3 Hash ========== */

typedef struct {
    uint32_t v[8];
    uint8_t buff[64];
    int buff_len;
    uint64_t data_bits_len;
    uint8_t hash_bytes[32];
    char hash_hex[65];
} SM3;

void sm3_init(SM3 *ctx);
void sm3_update_byte(SM3 *ctx, uint8_t b);
void sm3_update(SM3 *ctx, const uint8_t *data, size_t len);
void sm3_finish(SM3 *ctx);

/* ========== SM4 Block Cipher (CBC + PKCS7) ========== */

typedef struct {
    uint32_t rk[32];
    uint8_t iv[16];
} SM4;

void sm4_init(SM4 *ctx);
void sm4_set_key(SM4 *ctx, const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len);
/* Returns malloc'd hex string. Caller must free(). */
char *sm4_encrypt(SM4 *ctx, const char *plaintext);
/* Returns malloc'd plaintext string. Caller must free(). */
char *sm4_decrypt(SM4 *ctx, const char *ciphertext_hex);

/* ========== FpElement: field element modulo SM2_P ========== */

typedef struct { BigInt256 value; } FpElement;

/* ========== ECPoint: affine point on SM2 curve ========== */

typedef struct { FpElement x, y; int infinity; } ECPoint;

/* SM2 curve constants */
extern const BigInt256 SM2_P;
extern const BigInt256 SM2_N;

FpElement fp_new(BigInt256 v);
FpElement fp_from_hex(const char *s);
FpElement fp_zero(void);
FpElement fp_one(void);
int fp_is_zero(const FpElement *a);
FpElement fp_add(FpElement a, FpElement b);
FpElement fp_sub(FpElement a, FpElement b);
FpElement fp_mul(FpElement a, FpElement b);
FpElement fp_square(FpElement a);
FpElement fp_negate(FpElement a);
FpElement fp_invert(FpElement a);
FpElement fp_double(FpElement a);
FpElement fp_triple(FpElement a);
int fp_equal(FpElement a, FpElement b);
void fp_to_be_bytes(const FpElement *a, uint8_t out[32]);

ECPoint ec_point_new(FpElement x, FpElement y);
ECPoint ec_point_infinity(void);
ECPoint ec_point_generator(void);
ECPoint ec_point_from_hex_encoded(const char *hex);
void ec_point_to_hex_encoded(const ECPoint *p, char out[131]);
ECPoint ec_point_add(ECPoint p, ECPoint q);
ECPoint ec_point_multiply(ECPoint p, const BigInt256 *k);
int ec_point_is_on_curve(const ECPoint *p);

/* ========== SM2 Public Key Cryptography ========== */

void sm2_gen_keypair(char pri_hex[65], char pub_hex[131]);
ECPoint sm2_get_public_key(const BigInt256 *private_key);
/* Returns malloc'd hex string. Caller must free(). */
char *sm2_encrypt(const char *plaintext, const char *public_key_hex);
/* Returns malloc'd plaintext string. Caller must free(). NULL on error. */
char *sm2_decrypt(const char *ciphertext_hex, const char *private_key_hex);
/* Returns malloc'd signature string "r_hex h s_hex". Caller must free(). */
char *sm2_sign(const char *user_id, const char *message, const char *private_key_hex);
int sm2_verify(const char *user_id, const char *signature, const char *message, const char *public_key_hex);

/* SM2 Key Exchange */
typedef struct {
    char sa[65], sb[65];
    char ka[513], kb[513];
    ECPoint v;
    uint8_t za[32], zb[32];
    int success;
    char message[256];
} SM2KeySwapParams;

SM2KeySwapParams sm2_get_sb(int byte_len, ECPoint pA, ECPoint rA, ECPoint pB,
    const BigInt256 *dB, ECPoint rB, const BigInt256 *rb, const char *idA, const char *idB);
SM2KeySwapParams sm2_get_sa(int byte_len, ECPoint pB, ECPoint rB, ECPoint pA,
    const BigInt256 *dA, ECPoint rA, const BigInt256 *ra, const char *idA, const char *idB,
    const uint8_t *sb, size_t sb_len);
int sm2_check_sa(ECPoint v, const uint8_t *za, const uint8_t *zb, ECPoint rA, ECPoint rB,
    const uint8_t *sa, size_t sa_len);

/* ========== Utility ========== */

void bytes_to_hex(const uint8_t *data, size_t len, char *out);
int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len);

#endif /* SMX_H */
