#ifndef COMMON_GCM_H
#define COMMON_GCM_H

#include <stddef.h>
#include <stdint.h>

struct gcm_ctx;
typedef struct gcm_ctx GCM_CTX;

extern GCM_CTX *gcm_ctx_new(const unsigned char *secret);
extern void gcm_ctx_free(GCM_CTX *ctx);
extern void gcm_ctx_set_nonce(GCM_CTX *ctx, uint32_t nonce);
extern unsigned char *gcm_encrypt(GCM_CTX *gctx, const unsigned char *pt,
	const size_t ptlen, unsigned char *tag);
extern unsigned char *gcm_decrypt(GCM_CTX *gctx, const unsigned char *ct,
	const size_t ctlen, unsigned char *tag);

#endif /* COMMON_GCM_H */
