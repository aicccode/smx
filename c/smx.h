#ifndef SMX_H
#define SMX_H

#include <stdint.h>
#include <stddef.h>

/*
 * Failure convention: no function here crashes or hangs on bad input, given valid
 * pointers to buffers of the sizes documented. A function returning a pointer returns
 * NULL on failure, one returning int returns 0, and one returning a point returns the
 * point at infinity. Strings holding keys, points and signatures are parsed exactly:
 * the exact length, hex digits only, no prefix, no truncation and no reduction.
 *
 * The bigint256_* and fp_* functions are low-level arithmetic. Except for
 * mod_add, mod_sub and compare they make no promise about secret data; the SM2 and SM4
 * functions do not use the generic bigint256_mod_* code.
 */

/* ========== BigInt256: 256-bit unsigned integer, 4 x uint64 limbs, little-endian ========== */

typedef struct {
    uint64_t limbs[4];
} BigInt256;

BigInt256 bigint256_zero(void);
BigInt256 bigint256_one(void);
/*
 * Optional 0x prefix, then at most 64 hex digits. Anything else returns zero, which no
 * key or scalar check accepts.
 */
BigInt256 bigint256_from_hex(const char *hex);
/* Returns zero if the value does not fit in 256 bits. */
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
void bigint256_mod_pow(BigInt256 *r, const BigInt256 *base, const BigInt256 *exp,
                       const BigInt256 *m);
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

/*
 * Input beyond 2^61 - 1 bytes in total cannot be represented in SM3's 64-bit length, so
 * it is refused rather than wrapped: sm3_finish then leaves hash_hex empty and hash_bytes
 * zero. An empty hash_hex always means there is no digest: the context is not finished yet,
 * or it failed.
 *
 * sm3_finish resets the context for reuse. Calling it again at once keeps the same result.
 * Any update removes the digest of the previous message, so a stale one can never be read.
 */
void sm3_init(SM3 *ctx);
void sm3_update_byte(SM3 *ctx, uint8_t b);
void sm3_update(SM3 *ctx, const uint8_t *data, size_t len);
void sm3_finish(SM3 *ctx);

/* ========== SM4 Block Cipher (CBC + PKCS7) ==========
 *
 * WARNING: CBC gives confidentiality only, not integrity. A ciphertext can be altered
 * without detection, and a service that reveals whether decryption failed is a padding
 * oracle. Authenticate the ciphertext separately before decrypting (encrypt-then-MAC).
 *
 * WARNING: the IV in the context is used as is for every message, so encrypting two
 * messages with the same context leaks whether they share a prefix. Set a fresh random
 * IV for each message with sm4_set_key, or write ctx->iv directly.
 */

typedef struct {
    uint32_t rk[32];
    uint8_t iv[16];
    uint32_t key_state; /* internal: set only by a successful sm4_set_key */
} SM4;

void sm4_init(SM4 *ctx);
/*
 * key and iv must be exactly 16 bytes each. Anything else leaves ctx without a key, and
 * sm4_encrypt and sm4_decrypt then return NULL. Other lengths are never hashed or padded.
 */
void sm4_set_key(SM4 *ctx, const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len);
/*
 * Returns a malloc'd hex string, or NULL if no valid key is set or memory ran out. Caller
 * must free(). plaintext is a C string and ends at its first NUL; use sm4_encrypt_bytes
 * for binary data.
 */
char *sm4_encrypt(SM4 *ctx, const char *plaintext);
/*
 * Returns the malloc'd plaintext, terminated by a NUL, or NULL on any failure: no key set,
 * malformed hex (lowercase only, as sm4_encrypt emits), bad length or bad padding, all
 * indistinguishable. Caller must free(). The result is not checked as UTF-8.
 * Binary plaintext may hold NUL bytes that a C string cannot show; use sm4_decrypt_bytes
 * when it can.
 */
char *sm4_decrypt(SM4 *ctx, const char *ciphertext_hex);
/* Binary variants. out_len may be NULL; the result of decrypt is also NUL terminated. */
char *sm4_encrypt_bytes(SM4 *ctx, const uint8_t *data, size_t len);
uint8_t *sm4_decrypt_bytes(SM4 *ctx, const char *ciphertext_hex, size_t *out_len);

/* ========== FpElement: field element modulo SM2_P ========== */

typedef struct {
    BigInt256 value;
} FpElement;

/* ========== ECPoint: affine point on SM2 curve ========== */

typedef struct {
    FpElement x, y;
    int infinity;
} ECPoint;

/* SM2 curve constants */
extern const BigInt256 SM2_P;
extern const BigInt256 SM2_N;

/* Field constructors reduce mod p. Point parsing does not: it rejects x or y >= p. */
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
/*
 * Exactly 130 hex digits: 04, then x and y below p, on the curve. Returns infinity for
 * anything else, and infinity never passes ec_point_is_on_curve.
 */
ECPoint ec_point_from_hex_encoded(const char *hex);
void ec_point_to_hex_encoded(const ECPoint *p, char out[131]);
/* Variable time, for public points. Returns infinity if an input is not a valid point. */
ECPoint ec_point_add(ECPoint p, ECPoint q);
/* Constant time in k. Returns infinity if p is not a valid point, or if k = 0 mod n. */
ECPoint ec_point_multiply(ECPoint p, const BigInt256 *k);
/* 1 only for a finite point with x, y < p on the curve. Infinity gives 0. */
int ec_point_is_on_curve(const ECPoint *p);

/* ========== SM2 Public Key Cryptography ========== */

/*
 * Private keys are in [1, n-2], as exactly 64 hex digits. Public keys are as for
 * ec_point_from_hex_encoded. User IDs are at most 8191 bytes.
 *
 * Messages here are C strings and end at their first NUL. Use the _bytes variants for
 * binary data; otherwise a message with a NUL inside is silently cut short.
 *
 * Randomness comes only from the operating system. If it fails, these functions fail.
 */

/* On failure both outputs are empty strings. */
void sm2_gen_keypair(char pri_hex[65], char pub_hex[131]);
/* Returns infinity if private_key is outside [1, n-2]. */
ECPoint sm2_get_public_key(const BigInt256 *private_key);
/* Returns malloc'd hex string, C1 || C3 || C2. Caller must free(). NULL on error. */
char *sm2_encrypt(const char *plaintext, const char *public_key_hex);
/*
 * Returns malloc'd plaintext string. Caller must free(). NULL on error. Plaintext that may
 * hold NUL bytes needs sm2_decrypt_bytes.
 */
char *sm2_decrypt(const char *ciphertext_hex, const char *private_key_hex);
/* Returns malloc'd signature string "r_hex h s_hex". Caller must free(). NULL on error. */
char *sm2_sign(const char *user_id, const char *message, const char *private_key_hex);
/* 1 if valid, otherwise 0. r and s must be exactly 64 lowercase hex digits each. */
int sm2_verify(const char *user_id, const char *signature, const char *message,
               const char *public_key_hex);

/* Binary variants. out_len may be NULL; the result of decrypt is also NUL terminated. */
char *sm2_encrypt_bytes(const uint8_t *data, size_t len, const char *public_key_hex);
uint8_t *sm2_decrypt_bytes(const char *ciphertext_hex, const char *private_key_hex,
                           size_t *out_len);
char *sm2_sign_bytes(const char *user_id, const uint8_t *message, size_t len,
                     const char *private_key_hex);
int sm2_verify_bytes(const char *user_id, const char *signature, const uint8_t *message, size_t len,
                     const char *public_key_hex);

/*
 * SM2 Key Exchange. byte_len must be in [1, 256], which is what ka and kb can hold. All
 * points must be valid, all private values in [1, n-2], and Sa, Sb exactly 32 bytes. On
 * failure success is 0, the outputs are empty, and message holds a fixed description.
 */
typedef struct {
    char sa[65], sb[65];
    char ka[513], kb[513];
    ECPoint v;
    uint8_t za[32], zb[32];
    int success;
    char message[256];
} SM2KeySwapParams;

SM2KeySwapParams sm2_get_sb(int byte_len, ECPoint pA, ECPoint rA, ECPoint pB, const BigInt256 *dB,
                            ECPoint rB, const BigInt256 *rb, const char *idA, const char *idB);
SM2KeySwapParams sm2_get_sa(int byte_len, ECPoint pB, ECPoint rB, ECPoint pA, const BigInt256 *dA,
                            ECPoint rA, const BigInt256 *ra, const char *idA, const char *idB,
                            const uint8_t *sb, size_t sb_len);
int sm2_check_sa(ECPoint v, const uint8_t *za, const uint8_t *zb, ECPoint rA, ECPoint rB,
                 const uint8_t *sa, size_t sa_len);

/* ========== Utility ========== */

/* out must hold 2 * len + 1 characters. */
void bytes_to_hex(const uint8_t *data, size_t len, char *out);
/* Returns the byte count, or -1 for odd length, non-hex input or more than max_len bytes. */
int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len);

#endif /* SMX_H */
