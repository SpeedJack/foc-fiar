#include "client/proto.h"
#include "assertions.h"
#include "dh.h"
#include "error.h"
#include "mem.h"
#include "random.h"
#include <string.h>

typedef void *recv_func(PROTO_CTX *ctx, size_t *len);

static struct error *last_error = NULL;
static struct error invmsg_error = { INVMSG, "Received an invalid message." };

struct error *proto_get_last_error(void)
{
	return last_error;
}

void proto_clear_last_error(void)
{
	if (last_error && last_error != &invmsg_error)
		OPENSSL_free(last_error);
	last_error = NULL;
}

static void *recv_message(PROTO_CTX *ctx, enum msg_type type, size_t *len,
	recv_func *recv)
{
	assert(ctx && recv);
	proto_clear_last_error();
	size_t msglen;
	struct message *msg = recv(ctx, &msglen);
	if (!msg)
		return NULL;
	void *buf = OPENSSL_memdup(msg->body, msglen - sizeof(struct message));
	if (!buf) {
		REPORT_ERR(EALLOC, "Can not allocate space for the incoming message.");
		return NULL;
	}
	if (len)
		*len = msglen - sizeof(struct message);
	if (msg->type == type)
		return buf;
	if (msg->type == ERROR) {
		last_error = (struct error *)buf;
		REPORT_ERR(EPEERERR, last_error->message);
		return NULL;
	}
	OPENSSL_free(buf);
	last_error = &invmsg_error;
	return NULL;
}

bool proto_send_hello(PROTO_CTX *ctx, const char *username, uint16_t port,
	uint32_t nonce)
{
	assert(username);
	size_t msglen = MSG_SIZE_OF(struct client_hello);
	struct message *msg = OPENSSL_zalloc(msglen);
	if (!msg) {
		REPORT_ERR(EALLOC, "Can not allocate space for CLIENT_HELLO message.");
		return false;
	}
	msg->type = CLIENT_HELLO;
	struct client_hello *body = (struct client_hello *)msg->body;
	body->nonce = nonce;
	body->game_port = port;
	strncpy(body->username, username, MAX_USERNAME_LEN);
	body->username[MAX_USERNAME_LEN] = '\0';
	bool res = proto_send_sign(ctx, msg, msglen);
	OPENSSL_free(msg);
	return res;
}

X509 *proto_recv_cert(PROTO_CTX *ctx)
{
	struct server_cert *msg = recv_message(ctx, SERVER_CERT, NULL, proto_recv);
	if (!msg)
		return NULL;
	X509* cert = x509_deserialize(msg->cert, (size_t)msg->len);
	OPENSSL_free(msg);
	return cert;
}

struct server_hello *proto_recv_hello(PROTO_CTX *ctx)
{
	return (struct server_hello *)recv_message(ctx, SERVER_HELLO, NULL, proto_recv_verify);
}

bool proto_run_dh(PROTO_CTX *ctx)
{
	assert(ctx);
	DH_CTX *dhctx = dh_ctx_new();
	size_t pklen;
	unsigned char *pk = dh_gen_pubkey(dhctx, &pklen);
	if (!pk) {
		dh_ctx_free(dhctx);
		return false;
	}
	struct message *msg = OPENSSL_malloc(MSG_SIZE_OF(struct dhkey) + pklen);
	msg->type = DHKEY;
	struct dhkey *my = (struct dhkey *)msg->body;
	my->nonce = random_nonce();
	my->len = (uint32_t)pklen;
	memcpy(my->key, pk, pklen);
	OPENSSL_free(pk);
	if (!proto_send_sign(ctx, msg, MSG_SIZE_OF(struct dhkey) + pklen)) {
		OPENSSL_free(msg);
		dh_ctx_free(dhctx);
		return false;
	}
	struct dhkey *peer = (struct dhkey *)recv_message(ctx, DHKEY, NULL, proto_recv_verify);
	if (!peer) {
		OPENSSL_free(msg);
		dh_ctx_free(dhctx);
		return false;
	}
	if (peer->nonce != my->nonce) {
		REPORT_ERR(EINVMSG, "Received a signed message with a wrong nonce.");
		OPENSSL_free(peer);
		OPENSSL_free(msg);
		dh_ctx_free(dhctx);
		return false;
	}
	OPENSSL_free(msg);
	unsigned char *secret = dh_derive_secret(dhctx, peer->key, (size_t)peer->len);
	OPENSSL_free(peer);
	if (secret) {
		mem_dump("DIFFIE-HELLMAN HASHED SECRET", secret, 32);
		proto_ctx_set_secret(ctx, secret);
	}
	dh_ctx_free(dhctx);
	return !!secret;
}
