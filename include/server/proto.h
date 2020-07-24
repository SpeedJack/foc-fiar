#ifndef SERVER_PROTO_H
#define SERVER_PROTO_H

#include "server/x509.h"
#include "messages.h"
#include "protocol.h"

extern bool proto_send_cert(PROTO_CTX *ctx, X509 *cert);
extern bool proto_send_hello(PROTO_CTX *ctx, const char *username);
extern bool proto_send_player_list(PROTO_CTX *ctx, struct user_list *list);
extern bool proto_send_current_error(PROTO_CTX *ctx);
extern bool proto_send_chall_req(PROTO_CTX *ctx, char *username);
extern bool proto_send_chall_res(PROTO_CTX *ctx, bool accept);
extern bool proto_send_client_info(PROTO_CTX *ctx, const char *addr,
	uint16_t port, EVP_PKEY *pkey, uint32_t nonce);

#endif /* SERVER_PROTO_H */
