#include "client/proto.h"
#include "assertions.h"
#include "net.h"
#include "error.h"
#include "random.h"
#include <string.h>

bool proto_send_hello(PROTO_CTX *ctx, const char *username, uint16_t port)
{
	assert(username);
	struct client_hello msg;
	memset(&msg, 0, sizeof(struct client_hello));
	strncpy(msg.username, username, MAX_USERNAME_LEN);
	msg.username[MAX_USERNAME_LEN] = '\0';
	msg.game_port = port;
	return proto_send_sign(ctx, CLIENT_HELLO, &msg, sizeof(struct client_hello));
}

X509 *proto_recv_cert(PROTO_CTX *ctx)
{
	size_t msglen;
	struct server_cert *msg = (struct server_cert *)proto_recv_msg_type(ctx,
		SERVER_CERT, &msglen);
	if (!msg)
		return NULL;
	if (msg->len != msglen - sizeof(uint32_t)) {
		REPORT_ERR(EINVMSG, "Invalid certificate length.");
		return NULL;
	}
	X509* cert = x509_deserialize(msg->cert, (size_t)msg->len);
	return cert;
}

struct server_hello *proto_recv_hello(PROTO_CTX *ctx)
{
	return (struct server_hello *)proto_recv_msg_type(ctx, SERVER_HELLO, NULL);
}

struct chall_req *proto_recv_chall_req(PROTO_CTX *ctx)
{
	return (struct chall_req *)proto_recv_msg_type(ctx, CHALLENGE_REQ, NULL);
}

bool proto_send_chall_res(PROTO_CTX *ctx, bool accept)
{
	struct chall_res res;
	res.accept = accept;
	return proto_send_gcm(ctx, CHALLENGE_RES, &res, sizeof(struct chall_res));
}

PROTO_CTX *proto_connect_to_server(const char *addr, uint16_t port, EVP_PKEY *privkey, int ipv, int *sock)
{
	assert(addr && privkey && sock);
	char service[6];
	snprintf(service, 6, "%d", port);
	struct addrinfo *serveraddr = net_getaddrinfo(addr, service,
		ipv == 6 ? AF_INET6 : ipv == 4 ? AF_INET : AF_UNSPEC, SOCK_STREAM);
	if (!serveraddr)
		return NULL;
	*sock = net_connect(*serveraddr);
	if (*sock == -1) {
		freeaddrinfo(serveraddr);
		return NULL;
	}
	return proto_ctx_new(*sock, serveraddr, privkey, NULL);
}

struct user_list *proto_ask_player_list(PROTO_CTX *ctx)
{
	if (!proto_send_gcm(ctx, PLAYER_LIST_REQ, NULL, 0))
		return NULL;
	size_t msglen;
	struct user_list *msg = (struct user_list *)proto_recv_msg_type(ctx, PLAYER_LIST, &msglen);
	if (!msg)
		return NULL;
	if (msglen - sizeof(struct user_list) != msg->count*sizeof(struct user)) {
		REPORT_ERR(EINVMSG, "Invalid message size.");
		return NULL;
	}
	return msg;
}

struct client_info *proto_recv_client_info(PROTO_CTX *ctx)
{
	size_t msglen;
	struct client_info *infos = (struct client_info *)proto_recv_msg_type(ctx, CLIENT_INFO, &msglen);
	if (!infos)
		return NULL;
	if (infos->keylen != msglen - sizeof(struct client_info)) {
		REPORT_ERR(EINVMSG, "Invalid key length.");
		return NULL;
	}
	return infos;

}

bool proto_chall(PROTO_CTX *ctx, const char *opponent,
	struct client_info **infos)
{
	assert(opponent && infos);
	*infos = NULL;
	struct chall_req req;
	memset(&req, 0, sizeof(struct chall_req));
	strncpy(req.username, opponent, MAX_USERNAME_LEN);
	req.username[MAX_USERNAME_LEN] = '\0';
	if (!proto_send_gcm(ctx, CHALLENGE_REQ, &req, sizeof(struct chall_req)))
		return false;
	struct chall_res *res = (struct chall_res *)proto_recv_msg_type(ctx, CHALLENGE_RES, NULL);
	if (!res)
		return false;
	if (!res->accept)
		return true;
	*infos = proto_recv_client_info(ctx);
	return !!infos;
}

struct game_move *proto_recv_game_move(PROTO_CTX *ctx)
{
	return (struct game_move *)proto_recv_msg_type(ctx, GAME_MOVE, NULL);
}

bool proto_send_game_move(PROTO_CTX *ctx, unsigned int col)
{
	struct game_move move;
	memset(&move, 0, sizeof(struct game_move));
	move.column = col;
	if (!proto_send_gcm(ctx, GAME_MOVE, &move, sizeof(struct game_move)))
		return false;
	return true;
}

bool proto_send_game_end(PROTO_CTX *ctx)
{
	return proto_send_gcm(ctx, GAME_END, NULL, 0);
}
