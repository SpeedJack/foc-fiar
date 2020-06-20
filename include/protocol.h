#ifndef COMMON_PROTOCOL_H
#define COMMON_PROTOCOL_H

#include <netdb.h>
#include <stdbool.h>
#include <openssl/evp.h>

#define MAGIC_NUMBER		0xDEC0DE

struct proto_ctx;
typedef struct proto_ctx PROTO_CTX;


extern PROTO_CTX *proto_ctx_new(int socket, struct addrinfo *peeraddr,
	EVP_PKEY *privkey, EVP_PKEY *peerkey);
extern void proto_ctx_set_peerkey(PROTO_CTX *ctx, EVP_PKEY *peerkey);
extern void proto_ctx_set_secret(PROTO_CTX *ctx, unsigned char *secret);
extern void proto_ctx_free(PROTO_CTX *ctx);
extern bool proto_send(PROTO_CTX *ctx, const void *data, const size_t len);
extern bool proto_send_sign(PROTO_CTX *ctx, const void *data, const size_t len);
extern bool proto_send_gcm(PROTO_CTX *ctx, const void *data, const size_t len);
extern bool proto_verify_last_msg(PROTO_CTX *ctx);
extern void *proto_recv(PROTO_CTX *ctx, size_t *len);
extern void *proto_recv_verify(PROTO_CTX *ctx, size_t *len);
extern void *proto_recv_gcm(PROTO_CTX *ctx, size_t *len);
extern void proto_clear_last_recv_msg(PROTO_CTX *ctx);

#endif /* COMMON_PROTOCOL_H */
