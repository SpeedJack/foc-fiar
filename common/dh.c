#include "dh.h"
#include "assertions.h"
#include "digest.h"
#include "error.h"
#include "memdbg.h"
#include "pem.h"
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

struct dh_ctx {
	EVP_PKEY *privkey;
	EVP_PKEY *peerkey;
};

static DH *get_dh2048(void)
{
	static unsigned char dhp_2048[] = {
		0xBA, 0x0A, 0x85, 0xA9, 0xB7, 0x06, 0x2D, 0x27, 0x5F, 0x88,
		0xCD, 0xD9, 0x84, 0x62, 0xEF, 0x50, 0xBE, 0xEC, 0xD6, 0xCE,
		0xC4, 0x1E, 0xEC, 0x82, 0x56, 0x06, 0x95, 0xBC, 0x2B, 0x33,
		0x8D, 0x00, 0xFD, 0x2B, 0x4E, 0x87, 0xC7, 0xF2, 0xE3, 0x22,
		0xF2, 0x81, 0x65, 0x73, 0xF7, 0x76, 0x80, 0xA2, 0x9E, 0xE1,
		0xB9, 0x42, 0x35, 0x57, 0x74, 0x38, 0xA1, 0xE9, 0x55, 0x15,
		0x62, 0x60, 0x6A, 0xAC, 0x45, 0xF9, 0x14, 0xE9, 0x80, 0x22,
		0xD3, 0x3F, 0xE3, 0x82, 0xA7, 0x32, 0x86, 0x57, 0xBC, 0xC4,
		0xBF, 0x5B, 0xBF, 0x4B, 0xDE, 0x69, 0xB6, 0x6C, 0xFF, 0x4A,
		0x19, 0xFA, 0x65, 0x3C, 0x36, 0x68, 0x6D, 0x7D, 0xBB, 0xD1,
		0xD1, 0xBE, 0x7D, 0x04, 0xE3, 0xD4, 0x61, 0xB6, 0xE8, 0xF3,
		0x12, 0x41, 0xB9, 0xEF, 0xCC, 0x2A, 0xAF, 0x3C, 0x41, 0x7E,
		0xC2, 0x0F, 0xF1, 0xF7, 0xF1, 0x81, 0xC1, 0x1E, 0xD5, 0x11,
		0xA1, 0xED, 0xDA, 0xAC, 0xD5, 0x41, 0x06, 0xCB, 0xF3, 0xEC,
		0xCF, 0xAF, 0x48, 0x54, 0x6F, 0xBD, 0x71, 0x44, 0xDE, 0xE1,
		0x1E, 0x10, 0x7F, 0x61, 0xAA, 0x88, 0xB7, 0xD8, 0xE9, 0xC2,
		0xEB, 0x2C, 0xD8, 0xFF, 0xC6, 0x8C, 0xA9, 0x10, 0xC6, 0x15,
		0xF0, 0x49, 0xF1, 0x7D, 0x96, 0x15, 0xE3, 0x42, 0x03, 0xC6,
		0xAE, 0xE7, 0xD8, 0xDA, 0x1C, 0x7E, 0x72, 0x87, 0x48, 0xFC,
		0xAF, 0x27, 0x6F, 0xD5, 0x6C, 0xC8, 0x63, 0x35, 0xDE, 0xB4,
		0xAD, 0x8B, 0x0B, 0x45, 0x92, 0x78, 0x32, 0xF1, 0x59, 0x98,
		0xA8, 0xB5, 0xCA, 0xC8, 0xB4, 0x74, 0xDF, 0xBC, 0xC0, 0x22,
		0x8A, 0x44, 0x36, 0xF2, 0x6A, 0x8F, 0x22, 0xA2, 0x52, 0x7A,
		0xD1, 0xAD, 0x81, 0x71, 0xD4, 0x92, 0xCE, 0x67, 0xA5, 0xBA,
		0x6A, 0x13, 0x1B, 0x5E, 0x3A, 0x8A, 0x48, 0xB9, 0x83, 0xEC,
		0x7C, 0x60, 0xC2, 0xFB, 0xED, 0x9B
	};
	static unsigned char dhg_2048[] = {
		0x02
	};
	DH *dh = DH_new();
	BIGNUM *p, *g;

	if (!dh) {
		REPORT_ERR(EOSSL, "DH_new() returned NULL.");
		return NULL;
	}
	p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
	g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
	if (!p || !g || !DH_set0_pqg(dh, p, NULL, g)) {
		DH_free(dh);
		BN_free(p);
		BN_free(g);
		REPORT_ERR(EOSSL, "Error during DH p and g generation.");
		return NULL;
	}
	return dh;
}

DH_CTX *dh_ctx_new(void)
{
	DH_CTX *ctx = OPENSSL_malloc(sizeof(DH_CTX));
	if (!ctx) {
		REPORT_ERR(EALLOC, "Can not allocate space for DH_CTX.");
		return NULL;
	}
	ctx->privkey = NULL;
	ctx->peerkey = NULL;
	return ctx;
}

unsigned char *dh_gen_pubkey(DH_CTX *dhctx, size_t *len)
{
	assert(dhctx && len);
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *dh_params;
	DH *dh = get_dh2048();
	if (!dh)
		return NULL;
	dh_params = EVP_PKEY_new();
	if (!dh_params) {
		REPORT_ERR(EOSSL, "EVP_PKEY_new() returned NULL.");
		goto clean_return_error;
	}
	if (EVP_PKEY_set1_DH(dh_params, dh) != 1) {
		REPORT_ERR(EOSSL, "EVP_PKEY_set1_DH() failed.");
		goto clean_return_error;
	}
	DH_free(dh);
	dh = NULL;
	ctx = EVP_PKEY_CTX_new(dh_params, NULL);
	if (!ctx) {
		REPORT_ERR(EOSSL, "EVP_PKEY_CTX_new() returned NULL.");
		goto clean_return_error;
	}
	EVP_PKEY *privkey = NULL;
	if (EVP_PKEY_keygen_init(ctx) != 1) {
		REPORT_ERR(EOSSL, "EVP_PKEY_keygen_init() failed.");
		goto clean_return_error;
	}
	if (EVP_PKEY_keygen(ctx, &privkey) != 1) {
		REPORT_ERR(EOSSL, "EVP_PKEY_keygen() failed.");
		goto clean_return_error;
	}
	EVP_PKEY_free(dh_params);
	EVP_PKEY_CTX_free(ctx);
	dhctx->privkey = privkey;
	return pem_serialize_pubkey(privkey, len);
clean_return_error:
	EVP_PKEY_free(dh_params);
	EVP_PKEY_CTX_free(ctx);
	if (dh)
		DH_free(dh);
	return NULL;
}

void dh_ctx_free(DH_CTX *ctx)
{
	EVP_PKEY_free(ctx->privkey);
	EVP_PKEY_free(ctx->peerkey);
	OPENSSL_clear_free(ctx, sizeof(DH_CTX));
}

bool dh_ctx_set_peerkey(DH_CTX *ctx, unsigned char *peerkey, size_t len)
{
	ctx->peerkey = pem_deserialize_pubkey(peerkey, len);
	return !!ctx->peerkey;
}

unsigned char *dh_derive_secret(DH_CTX *dhctx)
{
	assert(dhctx);
	EVP_PKEY_CTX *ctx = NULL;
	unsigned char *secret = NULL;
	ctx = EVP_PKEY_CTX_new(dhctx->privkey, NULL);
	if (!ctx) {
		REPORT_ERR(EOSSL, "EVP_PKEY_CTX_new() returned NULL.");
		goto clean_return_error;
	}
	if (EVP_PKEY_derive_init(ctx) != 1) {
		REPORT_ERR(EOSSL, "EVP_PKEY_derive_init() failed.");
		goto clean_return_error;
	}
	if (EVP_PKEY_derive_set_peer(ctx, dhctx->peerkey) != 1) {
		REPORT_ERR(EOSSL, "EVP_PKEY_derive_set_peer() failed.");
		goto clean_return_error;
	}
	size_t secretlen;
	if (EVP_PKEY_derive(ctx, NULL, &secretlen) != 1) {
		REPORT_ERR(EOSSL, "EVP_PKEY_derive() failed (1).");
		goto clean_return_error;
	}
	secret = (unsigned char *)OPENSSL_malloc(secretlen);
	if (!secret) {
		REPORT_ERR(EALLOC, "Can not allocate space for DH secret.");
		goto clean_return_error;
	}
	if (EVP_PKEY_derive(ctx, secret, &secretlen) != 1) {
		REPORT_ERR(EOSSL, "EVP_PKEY_derive() failed (2).");
		goto clean_return_error;
	}
	EVP_PKEY_CTX_free(ctx);
	unsigned char *hash = digest_sha256(secret, secretlen);
	OPENSSL_clear_free(secret, secretlen);
	memdbg_dump("DIFFIE-HELLMAN HASHED SECRET", hash, SHA256_DIGEST_LENGTH);
	return hash;
clean_return_error:
	EVP_PKEY_CTX_free(ctx);
	OPENSSL_free(secret);
	return NULL;
}
