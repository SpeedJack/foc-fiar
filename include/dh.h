#ifndef COMMON_DH_H
#define COMMON_DH_H

#include <stdbool.h>
#include <stddef.h>

#define DH_SECRET_LENGTH		32

struct dh_ctx;
typedef struct dh_ctx DH_CTX;

extern DH_CTX *dh_ctx_new(void);
extern unsigned char *dh_gen_pubkey(DH_CTX *dhctx, size_t *len);
extern bool dh_ctx_set_peerkey(DH_CTX *dhctx, unsigned char *peerkey, size_t len);
extern unsigned char *dh_derive_secret(DH_CTX *dhctx);
extern void dh_ctx_free(DH_CTX *ctx);

#endif /* COMMON_DH_H */
