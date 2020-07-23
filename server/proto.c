#include "server/proto.h"
#include "assertions.h"
#include "error.h"
#include "pem.h"
#include <string.h>

struct client_hello *proto_recv_hello(PROTO_CTX *ctx)
{
	return (struct client_hello *)proto_recv_msg_type(ctx, CLIENT_HELLO, NULL);
}

bool proto_send_cert(PROTO_CTX *ctx, X509 *cert)
{
	assert(cert);
	size_t len;
	unsigned char *serialized = x509_serialize_cert(cert, &len);
	if (!serialized)
		return false;
	struct server_cert *msg = OPENSSL_malloc(sizeof(struct server_cert) + len);
	if (!msg) {
		REPORT_ERR(EALLOC, "Can not allocate space for SERVER_CERT message.");
		OPENSSL_free(serialized);
		return false;
	}
	msg->len = (uint32_t)len;
	memcpy(msg->cert, serialized, len);
	OPENSSL_free(serialized);
	bool res = proto_send_plain(ctx, SERVER_CERT, msg, sizeof(struct server_cert) + len);
	OPENSSL_free(msg);
	return res;
}

bool proto_send_hello(PROTO_CTX *ctx, const char *username)
{
	assert(username);
	struct server_hello msg;
	memset(&msg, 0, sizeof(struct server_hello));
	strncpy(msg.peer_username, username, MAX_USERNAME_LEN);
	msg.peer_username[MAX_USERNAME_LEN] = '\0';
	return proto_send_sign(ctx, SERVER_HELLO, &msg, sizeof(struct server_hello));
}

bool proto_send_player_list(PROTO_CTX *ctx, struct user_list *list)
{
	assert(list);
	return proto_send_gcm(ctx, PLAYER_LIST, list,
		sizeof(struct user_list) + list->count*sizeof(struct user));
}

bool proto_send_chall_req(PROTO_CTX *ctx, char *username)
{
	assert(username);
	struct chall_req req;
	memset(&req, 0, sizeof(struct chall_req));
	strncpy(req.username, username, MAX_USERNAME_LEN);
	req.username[MAX_USERNAME_LEN] = '\0';
	return proto_send_gcm(ctx, CHALLENGE_REQ, &req, sizeof(struct chall_req));
}

bool proto_send_chall_res(PROTO_CTX *ctx, bool accept)
{
	struct chall_res res;
	res.accept = accept;
	return proto_send_gcm(ctx, CHALLENGE_RES, &res, sizeof(struct chall_res));
}

bool proto_send_client_info(PROTO_CTX *ctx, const char *addr, uint16_t port,
	EVP_PKEY *pkey, uint32_t nonce)
{
	assert(addr && pkey);
	size_t keylen;
	unsigned char *key = pem_serialize_pubkey(pkey, &keylen);
	if (!key)
		return false;
	size_t msglen = sizeof(struct client_info) + keylen;
	struct client_info *msg = OPENSSL_malloc(msglen);
	if (!msg) {
		OPENSSL_clear_free(key, keylen);
		return false;
	}
	memset(msg, 0, msglen);
	strncpy(msg->address, addr, ADDRSTRLEN - 1);
	msg->address[ADDRSTRLEN - 1] = '\0';
	msg->game_port = port;
	msg->dhnonce = nonce;
	msg->keylen = (uint32_t)keylen;
	memcpy(msg->key, key, keylen);
	bool res = proto_send_gcm(ctx, CLIENT_INFO, msg, msglen);
	OPENSSL_clear_free(key, keylen);
	OPENSSL_clear_free(msg, msglen);
	return res;
}

bool proto_send_current_error(PROTO_CTX *ctx)
{
	enum error_code code = error_get_net_code();
	char *msg = error_get_message();
	error_print();
	bool res = proto_send_error(ctx, code, msg);
	if (msg)
		OPENSSL_free(msg);
	return res;
}
