#ifndef CLIENT_PROTO_H
#define CLIENT_PROTO_H

#include "client/x509.h"
#include "messages.h"
#include "protocol.h"

extern enum err_code proto_get_last_error(void);
extern bool proto_send_error(PROTO_CTX *ctx, enum err_code code, const char *message);
extern bool proto_send_hello(PROTO_CTX *ctx, const char *username, uint16_t port,
	uint32_t nonce);
extern X509 *proto_recv_cert(PROTO_CTX *ctx);
extern struct server_hello *proto_recv_hello(PROTO_CTX *ctx);
extern bool proto_run_dh(PROTO_CTX *ctx);

#endif /* CLIENT_PROTO_H */
