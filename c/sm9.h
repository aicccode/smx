#ifndef SMX_SM9_H
#define SMX_SM9_H

#include <stddef.h>
#include <stdint.h>

/*
 * SM9 identity-based cryptography (GB/T 38635): signatures, key encapsulation, encryption and
 * key exchange over the 256-bit BN curve of the standard. Included by smx.h.
 *
 * Encodings, all hex: scalars 64 digits; G1 points 04 || x || y (130 digits); G2 points
 * 04 || x1 || x0 || y1 || y0 (258 digits); signatures h || S (194 digits); ciphertexts
 * C1 || C3 || C2 with C1 a G1 point. Output is always lowercase.
 *
 * Input rules, as for SM2 here: keys, public points, R_A/R_B, r and confirmation values are
 * accepted in either case, but must be exactly the right length and decode to a valid value
 * (scalars in [1, N-1]; points on the curve, coordinates below q, not the identity; G2 points
 * in the order-N subgroup). Signatures and ciphertexts must be lowercase, the one spelling this
 * library produces. User IDs are C strings, so UTF-8 bytes up to the first NUL; empty IDs are
 * allowed. hid is any value in [0, 255].
 *
 * Failure convention: functions returning int return 1 on success and 0 on failure (verify:
 * 1 valid, 0 anything else), pointer results are NULL on failure, and output buffers are then
 * empty strings. Randomness comes only from the operating system; if it fails, these fail.
 *
 * Secret scalars (master keys, r, and the scalars derived from them) and private keys are
 * processed in constant time. The SM4 mode uses this branch's table-based SM4 (not
 * cache-timing resistant; see smx.h).
 */

#define SM9_HID_SIGN 0x01
#define SM9_HID_EXCHANGE 0x02
#define SM9_HID_ENCRYPT 0x03

/* encryption modes; the ciphertext does not record the mode, so decryption takes it too */
#define SM9_MODE_STREAM 0 /* C2 = M xor KDF output */
#define SM9_MODE_SM4 1    /* C2 = SM4-ECB(K1, PKCS#7(M)) */

/* sizes of the hex output buffers, terminator included */
#define SM9_SCALAR_HEX_SIZE 65
#define SM9_G1_HEX_SIZE 131
#define SM9_G2_HEX_SIZE 259
#define SM9_SIGNATURE_HEX_SIZE 195
#define SM9_HASH_HEX_SIZE 65

/* the largest key_len of sm9_exchange_respond and sm9_exchange_confirm, in bytes */
#define SM9_MAX_EXCHANGE_KEY_BYTES (1024 * 1024)

/* ---- keys ---- */

/* Signing master key pair: ks and Ppub-s = [ks]P2 (G2). */
int sm9_gen_sign_master_key(char master_private_hex[SM9_SCALAR_HEX_SIZE],
                            char master_public_hex[SM9_G2_HEX_SIZE]);
int sm9_sign_master_public_key(const char *master_private_hex,
                               char master_public_hex[SM9_G2_HEX_SIZE]);
/* ds = [ks / (H1(ID || hid) + ks)]P1, a G1 point. Fails if H1(ID || hid) + ks = 0 mod N. */
int sm9_gen_sign_user_key(const char *master_private_hex, const char *user_id, int hid,
                          char user_private_hex[SM9_G1_HEX_SIZE]);

/* Encryption master key pair: ke and Ppub-e = [ke]P1 (G1). Also used for key exchange. */
int sm9_gen_enc_master_key(char master_private_hex[SM9_SCALAR_HEX_SIZE],
                           char master_public_hex[SM9_G1_HEX_SIZE]);
int sm9_enc_master_public_key(const char *master_private_hex,
                              char master_public_hex[SM9_G1_HEX_SIZE]);
/* de = [ke / (H1(ID || hid) + ke)]P2, a G2 point. */
int sm9_gen_enc_user_key(const char *master_private_hex, const char *user_id, int hid,
                         char user_private_hex[SM9_G2_HEX_SIZE]);

/* ---- signatures ---- */

int sm9_sign(const char *message, const char *user_private_hex, const char *master_public_hex,
             char signature_hex[SM9_SIGNATURE_HEX_SIZE]);
int sm9_sign_bytes(const uint8_t *message, size_t len, const char *user_private_hex,
                   const char *master_public_hex, char signature_hex[SM9_SIGNATURE_HEX_SIZE]);
/* 1 if valid; 0 for an invalid signature and for any malformed input. */
int sm9_verify(const char *message, const char *signature_hex, const char *user_id,
               const char *master_public_hex, int hid);
int sm9_verify_bytes(const uint8_t *message, size_t len, const char *signature_hex,
                     const char *user_id, const char *master_public_hex, int hid);

/* ---- encryption ---- */

/*
 * Returns the malloc'd ciphertext hex, or NULL. Caller must free(). The plaintext must not be
 * empty. sm9_encrypt takes a C string, which ends at its first NUL.
 */
char *sm9_encrypt(const char *plaintext, const char *user_id, const char *master_public_hex,
                  int hid, int mode);
char *sm9_encrypt_bytes(const uint8_t *data, size_t len, const char *user_id,
                        const char *master_public_hex, int hid, int mode);
/*
 * Returns the malloc'd plaintext, NUL terminated, or NULL on any failure, all alike. Caller
 * must free(). out_len may be NULL. C3 is checked in constant time before anything is
 * decrypted or unpadded.
 */
uint8_t *sm9_decrypt_bytes(const char *ciphertext_hex, const char *user_id,
                           const char *user_private_hex, int mode, size_t *out_len);
char *sm9_decrypt(const char *ciphertext_hex, const char *user_id, const char *user_private_hex,
                  int mode);

/* ---- key encapsulation ---- */

/*
 * key_hex must hold 2 * key_len + 1 characters; key_len is in [1, SM9_MAX_EXCHANGE_KEY_BYTES],
 * the same bound as the key exchange. The ciphertext C is a G1 point, lowercase.
 */
int sm9_encapsulate(const char *user_id, const char *master_public_hex, size_t key_len, int hid,
                    char *key_hex, char ciphertext_hex[SM9_G1_HEX_SIZE]);
int sm9_decapsulate(const char *ciphertext_hex, const char *user_id, const char *user_private_hex,
                    size_t key_len, char *key_hex);

/* ---- key exchange (initiator A, responder B, both under the encryption master key) ---- */

/* r is secret: keep it for the respond or confirm step, then erase it. R goes to the peer. */
int sm9_exchange_init(const char *peer_id, const char *master_public_hex, int hid,
                      char r_hex[SM9_SCALAR_HEX_SIZE], char R_hex[SM9_G1_HEX_SIZE]);

/*
 * On failure success is 0, every output is empty or NULL and message holds a fixed
 * description. shared_key is malloc'd hex of key_len bytes; release the result with
 * sm9_exchange_result_free, which erases it.
 */
typedef struct {
    int success;
    char message[64];
    char *shared_key;
    char s_b[SM9_HASH_HEX_SIZE]; /* respond: S_B, sent to A */
    char s_2[SM9_HASH_HEX_SIZE]; /* respond: what A must send back, for sm9_exchange_check */
    char s_a[SM9_HASH_HEX_SIZE]; /* confirm: S_A, sent to B */
} SM9ExchangeResult;

/* B, on receiving R_A. key_len in [1, SM9_MAX_EXCHANGE_KEY_BYTES]. */
SM9ExchangeResult sm9_exchange_respond(size_t key_len, const char *id_a, const char *id_b,
                                       const char *master_public_hex,
                                       const char *user_private_b_hex, const char *r_b_hex,
                                       const char *R_b_hex, const char *R_a_hex);
/* A, on receiving R_B and S_B; S_B is checked in constant time before any key is released. */
SM9ExchangeResult sm9_exchange_confirm(size_t key_len, const char *id_a, const char *id_b,
                                       const char *master_public_hex,
                                       const char *user_private_a_hex, const char *r_a_hex,
                                       const char *R_a_hex, const char *R_b_hex,
                                       const char *s_b_hex);
/* B's last step: 1 if S_A equals S_2 (constant time), otherwise 0. */
int sm9_exchange_check(const char *s_2_hex, const char *s_a_hex);
void sm9_exchange_result_free(SM9ExchangeResult *result);

#endif /* SMX_SM9_H */
