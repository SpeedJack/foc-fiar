#ifndef SERVER_PROTO_H
#define SERVER_PROTO_H

#include "server/x509.h"
#include "messages.h"
#include "../proto.h"

extern struct error *proto_get_last_error();
extern void proto_clear_last_error();
extern struct client_hello *proto_recv_hello(PROTO_CTX *ctx);
extern bool proto_send_cert(PROTO_CTX *ctx, X509 *cert);
extern bool proto_send_hello(PROTO_CTX *ctx, const char *username, uint32_t nonce);
extern bool proto_run_dh(PROTO_CTX *ctx);

#endif /* SERVER_PROTO_H */
