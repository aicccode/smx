#include "smx.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Demo only: plain HTTP, so anyone on the path can read and alter the traffic, including
 * the key exchange. A real deployment needs TLS, and authenticated keys.
 */
#define SERVER_URL "http://localhost:8080"
#define IDA "c-client@demo.aicc"
/* The largest response accepted; the protocol's messages are far smaller. */
#define MAX_RESPONSE_BYTES (1024 * 1024)

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

/* ========== Simple JSON helpers (flat objects only) ========== */

/* Extract a string value for a given key from JSON. Returns malloc'd string or
 * NULL. */
static char *json_get_string(const char *json, const char *key) {
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p)
        return NULL;
    p += strlen(pattern);
    while (*p == ' ' || *p == ':' || *p == '\t')
        p++;
    if (*p != '"')
        return NULL;
    p++;
    const char *end = p;
    while (*end && *end != '"') {
        if (*end == '\\' && end[1] != '\0')
            end++;
        end++;
    }
    if (*end != '"')
        return NULL; /* unterminated string */
    size_t len = (size_t)(end - p);
    char *result = (char *)malloc(len + 1);
    if (!result)
        return NULL;
    memcpy(result, p, len);
    result[len] = '\0';
    return result;
}

/* Extract a boolean value for a given key from JSON. */
static int json_get_bool(const char *json, const char *key) {
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p)
        return 0;
    p += strlen(pattern);
    while (*p == ' ' || *p == ':' || *p == '\t')
        p++;
    return strncmp(p, "true", 4) == 0;
}

/* ========== libcurl response buffer ========== */

typedef struct {
    char *data;
    size_t len;
} ResponseBuffer;

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    ResponseBuffer *buf = (ResponseBuffer *)userp;
    /* returning less than the size given makes curl abort the transfer */
    if (nmemb != 0 && total / nmemb != size)
        return 0;
    if (total > MAX_RESPONSE_BYTES || buf->len > MAX_RESPONSE_BYTES - total)
        return 0;
    char *tmp = (char *)realloc(buf->data, buf->len + total + 1);
    if (!tmp)
        return 0;
    buf->data = tmp;
    memcpy(buf->data + buf->len, contents, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

/* POST JSON to url, returns response body (malloc'd). Caller must free(). */
static char *post_json(const char *url, const char *json_body) {
    CURL *curl = curl_easy_init();
    if (!curl)
        return NULL;

    ResponseBuffer buf = {NULL, 0};
    buf.data = (char *)malloc(1);
    if (!buf.data) {
        curl_easy_cleanup(curl);
        return NULL;
    }
    buf.data[0] = '\0';

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
#endif
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(buf.data);
        return NULL;
    }
    return buf.data;
}

/* ========== JSON escape helper (for plaintext that may contain special chars)
 * ========== */

static char *json_escape(const char *s) {
    size_t len = 0;
    const char *p;
    for (p = s; *p; p++) {
        if (*p == '"' || *p == '\\')
            len += 2;
        else
            len++;
    }
    char *out = (char *)malloc(len + 1);
    if (!out)
        return NULL;
    char *q = out;
    for (p = s; *p; p++) {
        if (*p == '"' || *p == '\\')
            *q++ = '\\';
        *q++ = *p;
    }
    *q = '\0';
    return out;
}

/* ========== Main test flow ========== */

int main(void) {
    printf("=== SM2 Key Exchange Demo (C Client) ===\n\n");

    curl_global_init(CURL_GLOBAL_ALL);

    /* Step 1: Generate keypairs */
    printf("[1] Generating keypairs...\n");
    char priA[65], pubA[131], ra_hex[65], rA_pub[131];
    sm2_gen_keypair(priA, pubA);
    sm2_gen_keypair(ra_hex, rA_pub);
    if (priA[0] == '\0' || ra_hex[0] == '\0') {
        fprintf(stderr, "Could not get randomness from the operating system\n");
        curl_global_cleanup();
        return 1;
    }
    printf("  A public:  %.20s...\n", pubA);

    int keyLen = 16;

    /* Step 2: Key Exchange Init */
    printf("\n--- Step 2: Key Exchange Init ---\n");
    char init_body[512];
    snprintf(init_body, sizeof(init_body),
             "{\"IDa\":\"%s\",\"pA\":\"%s\",\"Ra\":\"%s\",\"keyLen\":%d}", IDA, pubA, rA_pub,
             keyLen);

    char *init_resp = post_json(SERVER_URL "/api/keyswap/init", init_body);
    if (!init_resp) {
        fprintf(stderr, "Failed to connect to server. Make sure Java server is "
                        "running on port 8080\n");
        curl_global_cleanup();
        return 1;
    }

    char *sessionId = json_get_string(init_resp, "sessionId");
    char *IDb = json_get_string(init_resp, "IDb");
    char *pB_hex = json_get_string(init_resp, "pB");
    char *Rb_hex = json_get_string(init_resp, "Rb");
    char *Sb_hex = json_get_string(init_resp, "Sb");

    check("init response has sessionId", sessionId != NULL);
    check("init response has pB", pB_hex != NULL);
    check("init response has Rb", Rb_hex != NULL);
    check("init response has Sb", Sb_hex != NULL);
    check("init response has IDb", IDb != NULL);
    if (!sessionId || !pB_hex || !Rb_hex || !Sb_hex || !IDb || strlen(sessionId) > 128) {
        fprintf(stderr, "Malformed init response\n");
        goto cleanup;
    }

    /* Step 3: Calculate Sa and Ka */
    printf("\n--- Step 3: Calculate Sa and Ka ---\n");

    BigInt256 dA = bigint256_from_hex(priA);
    BigInt256 ra = bigint256_from_hex(ra_hex);
    ECPoint pB = ec_point_from_hex_encoded(pB_hex);
    ECPoint rB = ec_point_from_hex_encoded(Rb_hex);
    ECPoint pA = ec_point_from_hex_encoded(pubA);
    ECPoint rA = ec_point_from_hex_encoded(rA_pub);

    uint8_t sb_bytes[32];
    if (pB.infinity || rB.infinity || hex_to_bytes(Sb_hex, sb_bytes, 32) != 32) {
        fprintf(stderr, "Invalid key material in init response\n");
        check("init response key material is valid", 0);
        goto cleanup;
    }

    SM2KeySwapParams resultA = sm2_get_sa(keyLen, pB, rB, pA, &dA, rA, &ra, IDA, IDb, sb_bytes, 32);
    check("getSa success", resultA.success);
    if (!resultA.success) {
        fprintf(stderr, "  Error: %s\n", resultA.message);
        goto cleanup;
    }
    printf("  Sa: %.16s...\n", resultA.sa);

    /* Step 4: Key Exchange Confirm */
    printf("\n--- Step 4: Key Exchange Confirm ---\n");
    char confirm_body[256];
    snprintf(confirm_body, sizeof(confirm_body), "{\"sessionId\":\"%s\",\"Sa\":\"%s\"}", sessionId,
             resultA.sa);

    char *confirm_resp = post_json(SERVER_URL "/api/keyswap/confirm", confirm_body);
    if (!confirm_resp) {
        fprintf(stderr, "Failed to send confirm request\n");
        goto cleanup;
    }

    int confirmed = json_get_bool(confirm_resp, "success");
    check("key exchange confirmed", confirmed);
    free(confirm_resp);

    if (!confirmed) {
        fprintf(stderr, "Key exchange confirmation failed\n");
        goto cleanup;
    }

    printf("\n  Key exchange completed.\n");

    /* Step 5: Bidirectional Crypto Test */
    printf("\n--- Step 5: Bidirectional Crypto Test ---\n");

    uint8_t ka_bytes[16];
    if (hex_to_bytes(resultA.ka, ka_bytes, 16) != 16) {
        fprintf(stderr, "Unexpected key length\n");
        goto cleanup;
    }
    /*
     * The protocol this demo interoperates with fixes a zero IV, which is safe only for one
     * message per key. Real code must use a fresh random IV for each message, and
     * authenticate the ciphertext: CBC alone gives no integrity.
     */
    uint8_t zero_iv[16];
    memset(zero_iv, 0, 16);

    SM4 sm4;
    sm4_init(&sm4);
    sm4_set_key(&sm4, ka_bytes, 16, zero_iv, 16);

    const char *clientPlaintext = "Hello from C Client!";
    char *clientCiphertext = sm4_encrypt(&sm4, clientPlaintext);
    if (!clientCiphertext) {
        fprintf(stderr, "Encryption failed\n");
        goto cleanup;
    }
    printf("  Client plaintext:  %s\n", clientPlaintext);
    printf("  Client ciphertext: %s\n", clientCiphertext);

    /* Build crypto test request */
    char *escaped_plain = json_escape(clientPlaintext);
    if (!escaped_plain) {
        free(clientCiphertext);
        goto cleanup;
    }
    size_t crypto_body_len =
        256 + strlen(sessionId) + strlen(clientCiphertext) + strlen(escaped_plain);
    char *crypto_body = (char *)malloc(crypto_body_len);
    if (!crypto_body) {
        free(escaped_plain);
        free(clientCiphertext);
        goto cleanup;
    }
    snprintf(crypto_body, crypto_body_len,
             "{\"sessionId\":\"%s\",\"clientCiphertext\":\"%s\","
             "\"clientPlaintext\":\"%s\"}",
             sessionId, clientCiphertext, escaped_plain);
    free(escaped_plain);

    char *crypto_resp = post_json(SERVER_URL "/api/crypto/test", crypto_body);
    free(crypto_body);
    if (!crypto_resp) {
        fprintf(stderr, "Failed to send crypto request\n");
        free(clientCiphertext);
        goto cleanup;
    }

    /* Verify server decrypted client message */
    int serverDecryptOk = json_get_bool(crypto_resp, "clientDecryptMatch");
    check("server decrypted client message", serverDecryptOk);

    /* Client decrypts server message */
    char *serverCiphertext = json_get_string(crypto_resp, "serverCiphertext");
    char *serverPlaintext = json_get_string(crypto_resp, "serverPlaintext");

    if (serverCiphertext && serverPlaintext) {
        char *decrypted = sm4_decrypt(&sm4, serverCiphertext);
        int clientDecryptOk = decrypted && strcmp(decrypted, serverPlaintext) == 0;
        check("client decrypted server message", clientDecryptOk);
        printf("  Server plaintext: %s\n", serverPlaintext);
        if (decrypted)
            printf("  Client decrypted: %s\n", decrypted);

        if (serverDecryptOk && clientDecryptOk)
            printf("\n  Bidirectional Crypto test PASSED!\n");
        else
            printf("\n  Bidirectional Crypto test FAILED!\n");

        free(decrypted);
    }

    free(serverCiphertext);
    free(serverPlaintext);
    free(crypto_resp);
    free(clientCiphertext);

cleanup:
    free(init_resp);
    free(sessionId);
    free(IDb);
    free(pB_hex);
    free(Rb_hex);
    free(Sb_hex);
    curl_global_cleanup();

    printf("\n=== Demo Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
