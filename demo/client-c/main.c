#include "smx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed = 0, failed = 0;

static void check(const char *name, int cond) {
    if (cond) {
        printf("  PASS: %s\n", name);
        passed++;
    } else {
        printf("  FAIL: %s\n", name);
        failed++;
    }
}

static void test_key_exchange_and_crypto(void) {
    printf("=== SM2 Key Exchange + SM4 Encrypt/Decrypt Demo ===\n\n");

    /* --- Step 1: Generate keypairs for A and B --- */
    printf("[1] Generating keypairs...\n");
    char priA[65], pubA[131], priB[65], pubB[131];
    sm2_gen_keypair(priA, pubA);
    sm2_gen_keypair(priB, pubB);
    printf("  A private: %.16s...\n", priA);
    printf("  A public:  %.20s...\n", pubA);
    printf("  B private: %.16s...\n", priB);
    printf("  B public:  %.20s...\n", pubB);

    /* --- Step 2: Generate ephemeral keypairs --- */
    printf("\n[2] Generating ephemeral keypairs...\n");
    char ra_hex[65], rA_pub[131], rb_hex[65], rB_pub[131];
    sm2_gen_keypair(ra_hex, rA_pub);
    sm2_gen_keypair(rb_hex, rB_pub);
    printf("  A ephemeral: %.16s...\n", ra_hex);
    printf("  B ephemeral: %.16s...\n", rb_hex);

    /* --- Step 3: Key exchange --- */
    printf("\n[3] Performing key exchange...\n");
    const char *idA = "ALICE123@YAHOO.COM";
    const char *idB = "BILL456@YAHOO.COM";
    int keyLen = 16;

    BigInt256 dA = bigint256_from_hex(priA);
    BigInt256 dB = bigint256_from_hex(priB);
    BigInt256 ra = bigint256_from_hex(ra_hex);
    BigInt256 rb = bigint256_from_hex(rb_hex);

    ECPoint pA = ec_point_from_hex_encoded(pubA);
    ECPoint pB = ec_point_from_hex_encoded(pubB);
    ECPoint rA = ec_point_from_hex_encoded(rA_pub);
    ECPoint rB = ec_point_from_hex_encoded(rB_pub);

    /* B computes Sb */
    SM2KeySwapParams resultB = sm2_get_sb(keyLen, pA, rA, pB, &dB, rB, &rb, idA, idB);
    check("B key exchange success", resultB.success);
    if (!resultB.success) {
        printf("  Error: %s\n", resultB.message);
        return;
    }
    printf("  Sb: %.16s...\n", resultB.sb);
    printf("  Kb: %s\n", resultB.kb);

    /* A computes Sa and Ka */
    uint8_t sb_bytes[32];
    hex_to_bytes(resultB.sb, sb_bytes, 32);

    SM2KeySwapParams resultA = sm2_get_sa(keyLen, pB, rB, pA, &dA, rA, &ra, idA, idB, sb_bytes, 32);
    check("A key exchange success", resultA.success);
    if (!resultA.success) {
        printf("  Error: %s\n", resultA.message);
        return;
    }
    printf("  Sa: %.16s...\n", resultA.sa);
    printf("  Ka: %s\n", resultA.ka);

    /* Verify Ka == Kb */
    check("Ka == Kb", strcmp(resultA.ka, resultB.kb) == 0);

    /* B verifies Sa */
    uint8_t sa_bytes[32];
    hex_to_bytes(resultA.sa, sa_bytes, 32);
    int sa_ok = sm2_check_sa(resultB.v, resultB.za, resultB.zb, rA, rB, sa_bytes, 32);
    check("B verifies Sa", sa_ok);

    /* --- Step 4: SM4 encrypt/decrypt with negotiated key --- */
    printf("\n[4] SM4 encryption with negotiated key...\n");
    uint8_t ka_bytes[16];
    hex_to_bytes(resultA.ka, ka_bytes, 16);
    uint8_t zero_iv[16];
    memset(zero_iv, 0, 16);

    SM4 sm4;
    sm4_init(&sm4);
    sm4_set_key(&sm4, ka_bytes, 16, zero_iv, 16);

    const char *plaintext = "Hello SM2 key exchange + SM4!";
    char *ciphertext = sm4_encrypt(&sm4, plaintext);
    printf("  Plaintext:  %s\n", plaintext);
    printf("  Ciphertext: %s\n", ciphertext);

    /* B decrypts with same key */
    SM4 sm4b;
    sm4_init(&sm4b);
    uint8_t kb_bytes[16];
    hex_to_bytes(resultB.kb, kb_bytes, 16);
    sm4_set_key(&sm4b, kb_bytes, 16, zero_iv, 16);

    char *decrypted = sm4_decrypt(&sm4b, ciphertext);
    check("SM4 decrypt with negotiated key", decrypted != NULL && strcmp(decrypted, plaintext) == 0);
    if (decrypted) printf("  Decrypted:  %s\n", decrypted);

    free(ciphertext);
    free(decrypted);
}

static void test_sm2_encrypt_decrypt(void) {
    printf("\n=== SM2 Encrypt/Decrypt Demo ===\n\n");

    char pri[65], pub[131];
    sm2_gen_keypair(pri, pub);

    const char *messages[] = {
        "Hello SM2!",
        "encryption standard",
        "\xe5\x9b\xbd\xe5\xaf\x86SM2\xe5\x85\xac\xe9\x92\xa5\xe5\x8a\xa0\xe5\xaf\x86", /* 国密SM2公钥加密 */
    };
    int num_msgs = 3;
    int i;

    for (i = 0; i < num_msgs; i++) {
        printf("[%d] Message: %s\n", i+1, messages[i]);
        char *encrypted = sm2_encrypt(messages[i], pub);
        check("  encrypt not null", encrypted != NULL);

        char *decrypted = sm2_decrypt(encrypted, pri);
        check("  decrypt matches", decrypted != NULL && strcmp(decrypted, messages[i]) == 0);

        if (decrypted) printf("  Decrypted: %s\n", decrypted);
        free(encrypted);
        free(decrypted);
    }
}

int main(void) {
    test_key_exchange_and_crypto();
    test_sm2_encrypt_decrypt();

    printf("\n=== Demo Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
