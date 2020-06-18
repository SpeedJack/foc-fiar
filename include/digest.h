#ifndef COMMON_DIGEST_H
#define COMMON_DIGEST_H

#include <openssl/evp.h>
#include <stdbool.h>
#include <stddef.h>

#define SHA256_DIGEST_LENGTH		32

struct digest_ctx;
typedef struct digest_ctx DIGEST_CTX;

extern unsigned char *digest_sha256(const unsigned char *input, size_t len);
extern DIGEST_CTX *digest_ctx_new(EVP_PKEY *privkey, EVP_PKEY *peerkey);
extern void digest_ctx_free(DIGEST_CTX *ctx);
extern unsigned char *digest_sign(const DIGEST_CTX *dctx,
	const unsigned char *msg, size_t len, size_t *slen);
extern bool digest_verify(const DIGEST_CTX *dctx, const unsigned char *msg,
	size_t len, const unsigned char *sig, size_t slen);

#endif /* COMMON_DIGEST_H */
