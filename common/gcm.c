#include "gcm.h"
#include "assertions.h"
#include "digest.h"
#include "error.h"
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct gcm_ctx {
	unsigned char key[16];
	unsigned char iv[12];
	uint32_t nonce;
	uint32_t enc_counter;
	uint32_t dec_counter;
};

GCM_CTX *gcm_ctx_new(const unsigned char *secret)
{
	GCM_CTX *ctx = OPENSSL_malloc(sizeof(GCM_CTX));
	if (!ctx) {
		REPORT_ERR(EALLOC, "Can not allocate space for GCM_CTX.");
		return NULL;
	}
	memcpy(&ctx->key, secret, sizeof(ctx->key));
	memcpy(&ctx->iv, secret + 20, sizeof(ctx->iv));
	ctx->nonce = 0;
	ctx->enc_counter = 0;
	ctx->dec_counter = 0;
	return ctx;
}

void gcm_ctx_free(GCM_CTX *ctx)
{
	OPENSSL_free(ctx);
}

void gcm_ctx_set_nonce(GCM_CTX *ctx, uint32_t nonce)
{
	ctx->nonce = nonce;
}

static bool ctx_update(struct gcm_ctx *ctx, bool enc)
{
	unsigned char *input = OPENSSL_malloc(sizeof(ctx->iv) + 2*sizeof(uint32_t));
	if (!input) {
		REPORT_ERR(EALLOC, "Can not allocate space for GCM IV derivation.");
		return false;
	}
	memcpy(input, enc ? &ctx->enc_counter : &ctx->dec_counter, sizeof(uint32_t));
	memcpy(input + sizeof(uint32_t), ctx->iv, sizeof(ctx->iv));
	memcpy(input + sizeof(uint32_t) + sizeof(ctx->iv), &ctx->nonce, sizeof(uint32_t));
	unsigned char *hash = digest_sha256(input, sizeof(ctx->iv) + 2*sizeof(uint32_t));
	if (!hash) {
		OPENSSL_free(input);
		return false;
	}
	memcpy(ctx->iv, &hash[9], sizeof(ctx->iv));
	OPENSSL_free(input);
	ctx->enc_counter++;
	ctx->dec_counter++;
	return true;
}

unsigned char *gcm_encrypt(struct gcm_ctx *gctx, const unsigned char *pt, size_t len, unsigned char *tag)
{
	if (!ctx_update(gctx, true))
		return NULL;
	unsigned char *ct = NULL;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		REPORT_ERR(EOSSL, "EVP_CIPHER_CTX_new() returned NULL.");
		return NULL;
	}
	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
		REPORT_ERR(EOSSL, "EVP_EncryptInit_ex() failed (1).");
		goto clean_return_error;
	}
	if (EVP_EncryptInit_ex(ctx, NULL, NULL, gctx->key, gctx->iv) != 1) {
		REPORT_ERR(EOSSL, "EVP_EncryptInit_ex() failed (2).");
		goto clean_return_error;
	}
	ct = OPENSSL_malloc(len);
	if (!ct) {
		REPORT_ERR(EALLOC, "Can not allocate space for GCM ciphertext.");
		goto clean_return_error;
	}
	int outlen;
	if (EVP_EncryptUpdate(ctx, ct, &outlen, pt, len) != 1) {
		REPORT_ERR(EOSSL, "EVP_EncryptUpdate() failed.");
		goto clean_return_error;
	}
	assert(outlen == (int)len);
	if (EVP_EncryptFinal_ex(ctx, ct + len, &outlen) != 1) {
		REPORT_ERR(EOSSL, "EVP_EncryptFinal() failed.");
		goto clean_return_error;
	}
	assert(outlen == 0);
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
		REPORT_ERR(EOSSL, "EVP_CIPHER_CTX_ctrl() failed.");
		goto clean_return_error;
	}
	EVP_CIPHER_CTX_free(ctx);
	return ct;
clean_return_error:
	if (ct)
		OPENSSL_free(ct);
	EVP_CIPHER_CTX_free(ctx);
	return NULL;
}

unsigned char *gcm_decrypt(struct gcm_ctx *gctx, const unsigned char *ct, size_t len, unsigned char *tag)
{
	if (!ctx_update(gctx, false))
		return NULL;
	unsigned char *pt = NULL;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		REPORT_ERR(EOSSL, "EVP_CIPHER_CTX_new() returned NULL.");
		return NULL;
	}
	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
		REPORT_ERR(EOSSL, "EVP_DecryptInit_ex() failed (1).");
		goto clean_return_error;
	}
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, gctx->key, gctx->iv) != 1) {
		REPORT_ERR(EOSSL, "EVP_DecryptInit_ex() failed (2).");
		goto clean_return_error;
	}
	pt = OPENSSL_malloc(len);
	if (!pt) {
		REPORT_ERR(EALLOC, "Can not allocate space for GCM plaintext.");
		goto clean_return_error;
	}
	int outlen;
	if (EVP_DecryptUpdate(ctx, pt, &outlen, ct, len) != 1) {
		REPORT_ERR(EOSSL, "EVP_DecryptUpdate() failed.");
		goto clean_return_error;
	}
	assert(outlen == (int)len);
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) {
		REPORT_ERR(EOSSL, "EVP_CIPHER_CTX_ctrl() failed.");
		goto clean_return_error;
	}
	if (EVP_DecryptFinal_ex(ctx, pt + len, &outlen) <= 0) {
		REPORT_ERR(EOSSL, "EVP_DecryptFinal() failed.");
		goto clean_return_error;
	}
	assert(outlen == 0);
	EVP_CIPHER_CTX_free(ctx);
	return pt;
clean_return_error:
	if (pt)
		OPENSSL_free(pt);
	EVP_CIPHER_CTX_free(ctx);
	return NULL;
}
