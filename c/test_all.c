#include "smx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed = 0, failed = 0;

static void assert_str_eq(const char *name, const char *got, const char *expected) {
    if (strcmp(got, expected) == 0) {
        printf("  PASS: %s\n", name);
        passed++;
    } else {
        printf("  FAIL: %s\n    got:      %s\n    expected: %s\n", name, got, expected);
        failed++;
    }
}

static void assert_true(const char *name, int cond) {
    if (cond) {
        printf("  PASS: %s\n", name);
        passed++;
    } else {
        printf("  FAIL: %s\n", name);
        failed++;
    }
}

/* ========== SM3 Tests ========== */

static void test_sm3_abc(void) {
    SM3 sm3;
    sm3_init(&sm3);
    sm3_update(&sm3, (const uint8_t *)"abc", 3);
    sm3_finish(&sm3);
    assert_str_eq("SM3(abc)", sm3.hash_hex,
        "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0");
}

static void test_sm3_empty(void) {
    SM3 sm3;
    sm3_init(&sm3);
    sm3_update(&sm3, (const uint8_t *)"", 0);
    sm3_finish(&sm3);
    assert_str_eq("SM3(empty)", sm3.hash_hex,
        "1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B");
}

/* ========== SM4 Tests ========== */

static void test_sm4_encrypt_decrypt(void) {
    const char *key = "this is the key";
    const char *iv  = "this is the iv";
    const char *plaintext = "\xe5\x9b\xbd\xe5\xaf\x86SM4\xe5\xaf\xb9\xe7\xa7\xb0\xe5\x8a\xa0\xe5\xaf\x86\xe7\xae\x97\xe6\xb3\x95"; /* 国密SM4对称加密算法 UTF-8 */

    SM4 sm4;
    sm4_init(&sm4);
    sm4_set_key(&sm4, (const uint8_t *)key, strlen(key),
                      (const uint8_t *)iv, strlen(iv));

    char *ciphertext = sm4_encrypt(&sm4, plaintext);
    assert_str_eq("SM4 encrypt", ciphertext,
        "09908004c24cece806ee6dc2d6a3d154907048fb96d0201a8c47f4f1e03995bc");

    char *decrypted = sm4_decrypt(&sm4, ciphertext);
    assert_str_eq("SM4 decrypt", decrypted, plaintext);

    free(ciphertext);
    free(decrypted);
}

/* ========== SM2 Tests ========== */

static void test_sm2_keypair(void) {
    char pri[65], pub[131];
    sm2_gen_keypair(pri, pub);
    assert_true("SM2 keypair pri length == 64", strlen(pri) == 64);
    assert_true("SM2 keypair pub length == 130", strlen(pub) == 130);
    assert_true("SM2 keypair pub starts with 04", pub[0] == '0' && pub[1] == '4');
}

static void test_sm2_encrypt_decrypt(void) {
    char pri[65], pub[131];
    sm2_gen_keypair(pri, pub);
    const char *message = "encryption standard";

    char *encrypted = sm2_encrypt(message, pub);
    assert_true("SM2 encrypt not null", encrypted != NULL);

    char *decrypted = sm2_decrypt(encrypted, pri);
    assert_true("SM2 decrypt not null", decrypted != NULL);
    if (decrypted) {
        assert_str_eq("SM2 encrypt/decrypt roundtrip", decrypted, message);
    }

    free(encrypted);
    free(decrypted);
}

static void test_sm2_sign_verify(void) {
    char pri[65], pub[131];
    sm2_gen_keypair(pri, pub);
    const char *user_id = "ALICE123@YAHOO.COM";
    const char *message = "encryption standard";

    char *signature = sm2_sign(user_id, message, pri);
    assert_true("SM2 sign not null", signature != NULL);

    int valid = sm2_verify(user_id, signature, message, pub);
    assert_true("SM2 verify valid signature", valid);

    int invalid = sm2_verify(user_id, signature, "wrong message", pub);
    assert_true("SM2 verify wrong message fails", !invalid);

    free(signature);
}

static void test_sm2_key_exchange(void) {
    const char *idA = "ALICE123@YAHOO.COM";
    const char *idB = "BILL456@YAHOO.COM";

    BigInt256 dA = bigint256_from_hex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE");
    ECPoint pA = sm2_get_public_key(&dA);

    BigInt256 ra = bigint256_from_hex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563");
    ECPoint rA = sm2_get_public_key(&ra);

    BigInt256 dB = bigint256_from_hex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53");
    ECPoint pB = sm2_get_public_key(&dB);

    BigInt256 rb = bigint256_from_hex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80");
    ECPoint rB = sm2_get_public_key(&rb);

    SM2KeySwapParams resultB = sm2_get_sb(16, pA, rA, pB, &dB, rB, &rb, idA, idB);
    assert_true("SM2 key exchange B success", resultB.success);

    uint8_t sb_bytes[32];
    hex_to_bytes(resultB.sb, sb_bytes, 32);

    SM2KeySwapParams resultA = sm2_get_sa(16, pB, rB, pA, &dA, rA, &ra, idA, idB, sb_bytes, 32);
    assert_true("SM2 key exchange A success", resultA.success);

    assert_str_eq("SM2 key exchange Ka == Kb", resultA.ka, resultB.kb);

    uint8_t sa_bytes[32];
    hex_to_bytes(resultA.sa, sa_bytes, 32);
    int check = sm2_check_sa(resultB.v, resultB.za, resultB.zb, rA, rB, sa_bytes, 32);
    assert_true("SM2 key exchange B verifies Sa", check);
}

static void test_sm2_user_z(void) {
    char pri[65], pub[131];
    sm2_gen_keypair(pri, pub);
    ECPoint point = ec_point_from_hex_encoded(pub);

    SM3 sm3;
    sm3_init(&sm3);
    size_t uid_len = strlen("ALICE123@YAHOO.COM");
    uint16_t entl = (uint16_t)(uid_len * 8);
    sm3_update_byte(&sm3, (uint8_t)(entl >> 8));
    sm3_update_byte(&sm3, (uint8_t)(entl & 0xFF));
    sm3_update(&sm3, (const uint8_t *)"ALICE123@YAHOO.COM", uid_len);

    uint8_t buf[32];
    /* SM2_A */
    BigInt256 a_val = bigint256_from_hex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC");
    bigint256_to_be_bytes(&a_val, buf); sm3_update(&sm3, buf, 32);
    /* SM2_B */
    BigInt256 b_val = bigint256_from_hex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
    bigint256_to_be_bytes(&b_val, buf); sm3_update(&sm3, buf, 32);
    /* SM2_GX */
    BigInt256 gx_val = bigint256_from_hex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");
    bigint256_to_be_bytes(&gx_val, buf); sm3_update(&sm3, buf, 32);
    /* SM2_GY */
    BigInt256 gy_val = bigint256_from_hex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");
    bigint256_to_be_bytes(&gy_val, buf); sm3_update(&sm3, buf, 32);
    /* pub X, Y */
    fp_to_be_bytes(&point.x, buf); sm3_update(&sm3, buf, 32);
    fp_to_be_bytes(&point.y, buf); sm3_update(&sm3, buf, 32);
    sm3_finish(&sm3);

    assert_true("SM2 user Z length == 64 hex", strlen(sm3.hash_hex) == 64);
}

/* ========== Main ========== */

int main(void) {
    printf("=== SM3 Tests ===\n");
    test_sm3_abc();
    test_sm3_empty();

    printf("\n=== SM4 Tests ===\n");
    test_sm4_encrypt_decrypt();

    printf("\n=== SM2 Tests ===\n");
    test_sm2_keypair();
    test_sm2_encrypt_decrypt();
    test_sm2_sign_verify();
    test_sm2_key_exchange();
    test_sm2_user_z();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
