/* sha256.h - SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104), no dependencies. */
#ifndef VIGIL_SHA256_H
#define VIGIL_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_LEN 32
#define SHA256_HEX_LEN 64

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buf[64];
    size_t buflen;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[SHA256_DIGEST_LEN]);

void sha256(const void *data, size_t len, uint8_t out[SHA256_DIGEST_LEN]);
void hmac_sha256(const void *key, size_t keylen, const void *msg, size_t msglen,
                 uint8_t out[SHA256_DIGEST_LEN]);

/* out must hold SHA256_HEX_LEN + 1 bytes. */
void sha256_to_hex(const uint8_t digest[SHA256_DIGEST_LEN], char *out);

/* Constant-time comparison of two equal-length buffers. Returns 1 if equal. */
int ct_equal(const void *a, const void *b, size_t len);

#endif
