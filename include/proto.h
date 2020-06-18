#ifndef COMMON_PROTO_H
#define COMMON_PROTO_H

#include <netdb.h>
#include <stdbool.h>
#include <openssl/evp.h>

struct proto_ctx;
typedef struct proto_ctx PROTO_CTX;

extern PROTO_CTX *proto_ctx_new(int socket, struct addrinfo *peeraddr,
	EVP_PKEY *privkey, EVP_PKEY *peerkey);
extern void proto_ctx_free(PROTO_CTX *ctx);
extern bool proto_send(PROTO_CTX *ctx, const void *data, const size_t len);
extern bool proto_send_sign(PROTO_CTX *ctx, const void *data, const size_t len);
extern bool proto_send_gcm(PROTO_CTX *ctx, const void *data, const size_t len);
extern void *proto_recv(PROTO_CTX *ctx, size_t *len);
extern void *proto_recv_sign(PROTO_CTX *ctx, size_t *len);
extern void *proto_recv_gcm(PROTO_CTX *ctx, size_t *len);
extern bool proto_run_dh(PROTO_CTX *ctx);

#endif /* COMMON_PROTO_H */
