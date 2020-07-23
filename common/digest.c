#include "digest.h"
#include "assertions.h"
#include "error.h"

struct digest_ctx {
	EVP_PKEY *privkey;
	EVP_PKEY *peerkey;
};

unsigned char *digest_sha256(const unsigned char *input, size_t len)
{
	assert(input);
	unsigned char *hash = OPENSSL_malloc(SHA256_DIGEST_LENGTH);
	if (!hash) {
		REPORT_ERR(EALLOC, "Can not allocate space for the SHA-256 digest.");
		return NULL;
	}
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		REPORT_ERR(EOSSL, "EVP_MD_CTX_new() returned NULL.");
		return NULL;
	}
	if (EVP_DigestInit(ctx, EVP_sha256()) != 1) {
		REPORT_ERR(EOSSL, "EVP_DigestInit() failed.");
		goto clean_return_error;
	}
	if (EVP_DigestUpdate(ctx, input, len) != 1) {
		REPORT_ERR(EOSSL, "EVP_DigestUpdate() failed.");
		goto clean_return_error;
	}
	unsigned int outlen;
	if (EVP_DigestFinal(ctx, hash, &outlen) != 1) {
		REPORT_ERR(EOSSL, "EVP_DigestFinal() failed.");
		goto clean_return_error;
	}
	EVP_MD_CTX_free(ctx);
	assert(outlen == SHA256_DIGEST_LENGTH);
	return hash;
clean_return_error:
	EVP_MD_CTX_free(ctx);
	return NULL;
}

DIGEST_CTX *digest_ctx_new(EVP_PKEY *privkey, EVP_PKEY *peerkey)
{
	DIGEST_CTX *ctx = OPENSSL_malloc(sizeof(DIGEST_CTX));
	if (!ctx) {
		REPORT_ERR(EALLOC, "Can not allocate space for DIGEST_CTX.");
		return NULL;
	}
	ctx->privkey = privkey;
	ctx->peerkey = peerkey;
	return ctx;
}

void digest_ctx_set_peerkey(DIGEST_CTX *ctx, EVP_PKEY *peerkey)
{
	assert(ctx);
	ctx->peerkey = peerkey;
}

bool digest_ctx_can_verify(DIGEST_CTX *ctx)
{
	return ctx && ctx->peerkey;
}

bool digest_ctx_can_sign(DIGEST_CTX *ctx)
{
	return ctx && ctx->privkey;
}

void digest_ctx_free(DIGEST_CTX *ctx)
{
	EVP_PKEY_free(ctx->peerkey);
	OPENSSL_clear_free(ctx, sizeof(DIGEST_CTX));
}

unsigned char *digest_sign(const DIGEST_CTX *dctx, const unsigned char *msg,
	size_t len, size_t *slen)
{
	assert(dctx && msg && slen);
	unsigned char *sig = NULL;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		REPORT_ERR(EOSSL, "EVP_MD_CTX_new() returned NULL.");
		return NULL;
	}
	if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, dctx->privkey) != 1) {
		REPORT_ERR(EOSSL, "EVP_DigestSignInit() failed.");
		goto clean_return;
	}
	if (EVP_DigestSignUpdate(ctx, msg, len) != 1) {
		REPORT_ERR(EOSSL, "EVP_DigestSignUpdate() failed.");
		goto clean_return;
	}
	if (EVP_DigestSignFinal(ctx, NULL, slen) != 1) {
		REPORT_ERR(EOSSL, "EVP_DigestSignFinal() failed (1).");
		goto clean_return;
	}
	sig = OPENSSL_malloc(*slen);
	if (!sig) {
		REPORT_ERR(EALLOC, "OPENSSL_malloc() returned NULL.");
		goto clean_return;
	}
	if (EVP_DigestSignFinal(ctx, sig, slen) != 1) {
		REPORT_ERR(EOSSL, "EVP_DigestSignFinal() failed (2).");
		OPENSSL_free(sig);
		sig = NULL;
	}
clean_return:
	EVP_MD_CTX_free(ctx);
	return sig;
}

bool digest_verify(const DIGEST_CTX *dctx, const unsigned char *msg, size_t len,
	const unsigned char *sig, size_t slen)
{
	if (!dctx || !dctx->peerkey)
		return false;
	assert(msg && sig);
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		REPORT_ERR(EOSSL, "EVP_MD_CTX_new() returned NULL.");
		return false;
	}
	if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, dctx->peerkey) != 1) {
		REPORT_ERR(EOSSL, "EVP_DigestVerifyInit() failed.");
		goto clean_return_error;
	}
	if (EVP_DigestVerifyUpdate(ctx, msg, len) != 1) {
		REPORT_ERR(EOSSL, "EVP_DigestVerifyUpdate() failed.");
		goto clean_return_error;
	}
	int ret = EVP_DigestVerifyFinal(ctx, sig, slen);
	if (ret != 1 && ret != 0)
		REPORT_ERR(EOSSL, "EVP_DigestVerifyFinal() failed.");
	EVP_MD_CTX_free(ctx);
	return ret == 1;
clean_return_error:
	EVP_MD_CTX_free(ctx);
	return false;
}
