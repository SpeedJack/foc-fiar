#ifndef CLIENT_PROTO_H
#define CLIENT_PROTO_H

#include "client/x509.h"
#include "messages.h"
#include "protocol.h"

extern bool proto_send_hello(PROTO_CTX *ctx, const char *username, uint16_t port);
extern X509 *proto_recv_cert(PROTO_CTX *ctx);
extern struct server_hello *proto_recv_hello(PROTO_CTX *ctx);
extern PROTO_CTX *proto_connect_to_server(const char *addr, uint16_t port, EVP_PKEY *privkey, int ipv, int *sock);
extern struct user_list *proto_ask_player_list(PROTO_CTX *ctx);
extern struct chall_req *proto_recv_chall_req(PROTO_CTX *ctx);
extern bool proto_send_chall_res(PROTO_CTX *ctx, bool accept);
extern struct client_info *proto_recv_client_info(PROTO_CTX *ctx);
extern bool proto_chall(PROTO_CTX *ctx, const char *opponent,
	struct client_info **infos);

#endif /* CLIENT_PROTO_H */
