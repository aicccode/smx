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

/* ========== A small strict JSON reader ========== */

/* Nesting beyond this is refused rather than followed, so a deep document cannot overflow. */
#define JSON_MAX_DEPTH 32

static const char *json_skip_space(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    return p;
}

/* p is at the opening quote. Returns the position after the closing quote, or NULL. */
static const char *json_skip_string(const char *p) {
    p++;
    while (*p != '"') {
        if ((unsigned char)*p < 0x20)
            return NULL; /* the end of the text, or a raw control character */
        if (*p == '\\') {
            p++;
            if (*p == '\0')
                return NULL;
        }
        p++;
    }
    return p + 1;
}

/* Returns the position after the value at p, or NULL if it is malformed. */
static const char *json_skip_value(const char *p, int depth) {
    if (depth > JSON_MAX_DEPTH)
        return NULL;
    p = json_skip_space(p);
    if (*p == '"')
        return json_skip_string(p);
    if (*p == '{' || *p == '[') {
        char close = *p == '{' ? '}' : ']';
        int is_object = *p == '{';
        p = json_skip_space(p + 1);
        if (*p == close)
            return p + 1;
        for (;;) {
            if (is_object) {
                p = json_skip_space(p);
                if (*p != '"')
                    return NULL;
                p = json_skip_string(p);
                if (!p)
                    return NULL;
                p = json_skip_space(p);
                if (*p != ':')
                    return NULL;
                p++;
            }
            p = json_skip_value(p, depth + 1);
            if (!p)
                return NULL;
            p = json_skip_space(p);
            if (*p == close)
                return p + 1;
            if (*p != ',')
                return NULL;
            p++;
        }
    }
    if (strncmp(p, "true", 4) == 0)
        return p + 4;
    if (strncmp(p, "false", 5) == 0)
        return p + 5;
    if (strncmp(p, "null", 4) == 0)
        return p + 4;
    {
        char *end;
        strtod(p, &end);
        return end == p ? NULL : end;
    }
}

/* A whole document, one object and nothing after it. */
static int json_is_valid_object(const char *json) {
    const char *p = json_skip_space(json);
    if (*p != '{')
        return 0;
    p = json_skip_value(p, 0);
    return p && *json_skip_space(p) == '\0';
}

/*
 * The value of a top-level member of a document that passed json_is_valid_object, or NULL. It
 * walks the members, so that text inside some other value can never be taken for the key.
 */
static const char *json_find(const char *json, const char *key) {
    size_t key_len = strlen(key);
    const char *p = json_skip_space(json_skip_space(json) + 1);
    while (*p == '"') {
        const char *name = p + 1;
        const char *after = json_skip_string(p);
        size_t name_len = (size_t)(after - name) - 1;
        const char *value = json_skip_space(json_skip_space(after) + 1);
        if (name_len == key_len && memcmp(name, key, key_len) == 0)
            return value;
        p = json_skip_space(json_skip_value(value, 1));
        if (*p != ',')
            return NULL;
        p = json_skip_space(p + 1);
    }
    return NULL;
}

/* A string member, escapes decoded, as a malloc'd string. NULL if absent or another type. */
static char *json_get_string(const char *json, const char *key) {
    const char *p = json_find(json, key);
    const char *end;
    char *result, *q;
    if (!p || *p != '"')
        return NULL;
    end = json_skip_string(p);
    result = (char *)malloc((size_t)(end - p));
    if (!result)
        return NULL;
    q = result;
    for (p++; p < end - 1; p++) {
        if (*p != '\\') {
            *q++ = *p;
            continue;
        }
        p++;
        switch (*p) {
        case 'n':
            *q++ = '\n';
            break;
        case 't':
            *q++ = '\t';
            break;
        case 'r':
            *q++ = '\r';
            break;
        case 'b':
            *q++ = '\b';
            break;
        case 'f':
            *q++ = '\f';
            break;
        case 'u':
            /* nothing in this protocol needs them, and a NUL must not end the string early */
            free(result);
            return NULL;
        default:
            *q++ = *p;
            break;
        }
    }
    *q = '\0';
    return result;
}

/* True only for the literal true: not "true", "false" as a string, 1, or anything else. */
static int json_get_bool(const char *json, const char *key) {
    const char *p = json_find(json, key);
    const char *end;
    if (!p || strncmp(p, "true", 4) != 0)
        return 0;
    end = json_skip_space(p + 4);
    return *end == ',' || *end == '}';
}

/* Server text may hold anything: control characters reaching a terminal can drive it. */
static void print_untrusted(const char *label, const char *text) {
    const unsigned char *p = (const unsigned char *)text;
    fputs(label, stdout);
    for (; *p; p++)
        fputc(*p < 0x20 || *p == 0x7F ? '?' : *p, stdout);
    fputc('\n', stdout);
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

/*
 * POST JSON to url, returns the response body (malloc'd), or NULL for a network error, the
 * deadline passing, too much data, or anything other than one valid JSON object. Caller must
 * free().
 */
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
    /* a limit on the whole request, so a server dripping bytes cannot stall the client */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
#endif
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || !json_is_valid_object(buf.data)) {
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
        fprintf(stderr, "No valid response from the server on port 8080. Is it running?\n");
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

    /*
     * pB and IDb arrive in the same unauthenticated response as everything else, so an impostor
     * can send its own key and pass key confirmation. Only a key known in advance stops that.
     */
    {
        const char *pinned_hex = getenv("SM2_DEMO_SERVER_PUBKEY");
        if (pinned_hex && pinned_hex[0] != '\0') {
            ECPoint pinned = ec_point_from_hex_encoded(pinned_hex);
            int same = !pinned.infinity && bigint256_compare(&pinned.x.value, &pB.x.value) == 0 &&
                       bigint256_compare(&pinned.y.value, &pB.y.value) == 0;
            check("server key matches SM2_DEMO_SERVER_PUBKEY", same);
            if (!same) {
                fprintf(stderr, "Server public key does not match SM2_DEMO_SERVER_PUBKEY. "
                                "Refusing to continue.\n");
                goto cleanup;
            }
        } else {
            printf("  WARNING: the server is UNAUTHENTICATED. Set SM2_DEMO_SERVER_PUBKEY to pin\n"
                   "  its key; without that, an impostor can complete this exchange.\n");
        }
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
        print_untrusted("  Server plaintext: ", serverPlaintext);
        if (decrypted)
            print_untrusted("  Client decrypted: ", decrypted);

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
