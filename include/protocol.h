#ifndef COMMON_PROTOCOL_H
#define COMMON_PROTOCOL_H

#include "messages.h"
#include <netdb.h>
#include <stdbool.h>
#include <openssl/evp.h>

struct proto_ctx;
typedef struct proto_ctx PROTO_CTX;

extern PROTO_CTX *proto_ctx_new(int socket, struct addrinfo *peeraddr,
	EVP_PKEY *privkey, EVP_PKEY *peerkey);
extern void proto_ctx_set_peerkey(PROTO_CTX *ctx, EVP_PKEY *peerkey);
extern void proto_ctx_set_secret(PROTO_CTX *ctx, const unsigned char *secret);
extern void proto_clear_last_recv_msg(PROTO_CTX *ctx);
extern void proto_ctx_free(PROTO_CTX *ctx);
extern bool proto_send_plain(PROTO_CTX *ctx, enum msg_type type, const void *data, const size_t len);
extern bool proto_send_sign(PROTO_CTX *ctx, enum msg_type type, const void *data, const size_t len);
extern bool proto_send_gcm(PROTO_CTX *ctx, enum msg_type type, const void *data, const size_t len);
extern bool proto_send(PROTO_CTX *ctx, enum msg_type type, const void *data, const size_t len);
extern bool proto_verify_last_msg(PROTO_CTX *ctx);
extern void *proto_recv_plain(PROTO_CTX *ctx, enum msg_type *type, size_t *len);
extern void *proto_recv_verify(PROTO_CTX *ctx, enum msg_type *type, size_t *len);
extern void *proto_recv_gcm(PROTO_CTX *ctx, enum msg_type *type, size_t *len);
extern void *proto_recv(PROTO_CTX *ctx, enum msg_type *type, size_t *len);
extern void *proto_recv_msg_type(PROTO_CTX *ctx, enum msg_type type, size_t *len);
extern bool proto_run_dh(PROTO_CTX *ctx, bool send_first, uint32_t nonce);
extern bool proto_send_error(PROTO_CTX *ctx, enum error_code code, const char *text);

#endif /* COMMON_PROTOCOL_H */
