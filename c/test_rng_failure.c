/*
 * Built with -DSMX_TEST_RNG_FAILS or -DSMX_TEST_RNG_ALL_ONES (see check-fallbacks). Every
 * function that needs randomness must fail cleanly rather than use the output, or hang:
 * all-ones is never below n, so rejection sampling exhausts its retry limit.
 */
#include "smx.h"
#include <stdio.h>
#include <stdlib.h>

#define PUB                                                                                        \
    "0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"                           \
    "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"
#define PRI "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"

int main(void) {
    char pri[65] = "x", pub[131] = "x";
    int failed = 0;

    sm2_gen_keypair(pri, pub);
    if (pri[0] != '\0' || pub[0] != '\0') {
        printf("FAIL: keygen produced output\n");
        failed++;
    }
    if (sm2_encrypt("message", PUB) != NULL) {
        printf("FAIL: encrypt produced output\n");
        failed++;
    }
    if (sm2_sign("id", "message", PRI) != NULL) {
        printf("FAIL: sign produced output\n");
        failed++;
    }
    {
        /* SM9: the standard's encryption master public key */
        static const char epub[] = "04787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a8"
                                   "92ff769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f"
                                   "644c57a7b1";
        char mpri[65] = "x", mpub[259] = "x", r[65] = "x", big_r[131] = "x";
        char *ct;
        if (sm9_gen_sign_master_key(mpri, mpub) || mpri[0] != '\0' || mpub[0] != '\0' ||
            sm9_gen_enc_master_key(mpri, mpub) || mpri[0] != '\0') {
            printf("FAIL: SM9 master keygen produced output\n");
            failed++;
        }
        ct = sm9_encrypt("message", "Bob", epub, SM9_HID_ENCRYPT, SM9_MODE_STREAM);
        if (ct != NULL || sm9_exchange_init("Bob", epub, SM9_HID_EXCHANGE, r, big_r) ||
            r[0] != '\0') {
            printf("FAIL: SM9 encrypt or exchange produced output\n");
            failed++;
        }
        free(ct);
    }
    printf("=== RNG failure: %s ===\n", failed ? "FAILED" : "all clean");
    return failed ? 1 : 0;
}
