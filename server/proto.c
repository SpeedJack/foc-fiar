#include "server/x509.h"
#include "assertions.h"
#include "dh.h"
#include "error.h"
#include "messages.h"
#include "proto.h"
#include <string.h>

typedef void *recv_func(PROTO_CTX *ctx, size_t *len);

static struct error *last_error = NULL;
static struct error invmsg_error = { INVMSG, "Received an invalid message." };

struct error *proto_get_last_error()
{
	return last_error;
}

void proto_clear_last_error()
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
	OPENSSL_free(msg);
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

struct client_hello *proto_recv_hello(PROTO_CTX *ctx)
{
	return (struct client_hello *)recv_message(ctx, CLIENT_HELLO, NULL, proto_recv);
}

bool proto_send_cert(PROTO_CTX *ctx, X509 *cert)
{
	assert(cert);
	size_t len;
	unsigned char *serialized = x509_serialize_cert(cert, &len);
	if (!serialized)
		return false;
	size_t msglen = MSG_SIZE_OF(struct server_cert) + len;
	struct message *msg = OPENSSL_malloc(msglen);
	if (!msg) {
		REPORT_ERR(EALLOC, "Can not allocate space for SERVER_CERT message.");
		OPENSSL_free(serialized);
		return false;
	}
	msg->type = SERVER_CERT;
	struct server_cert *body = (struct server_cert *)msg->body;
	body->len = len;
	memcpy(body->cert, serialized, len);
	OPENSSL_free(serialized);
	bool res = proto_send_sign(ctx, msg, msglen);
	OPENSSL_free(msg);
	return res;
}

bool proto_send_hello(PROTO_CTX *ctx, const char *username, uint32_t nonce)
{
	assert(username);
	size_t msglen = MSG_SIZE_OF(struct server_hello);
	struct message *msg = OPENSSL_malloc(msglen);
	if (!msg) {
		REPORT_ERR(EALLOC, "Can not allocate space for SERVER_HELLO message.");
		return false;
	}
	msg->type = SERVER_HELLO;
	struct server_hello *body = (struct server_hello *)msg->body;
	body->nonce = nonce;
	strncpy(body->peer_username, username, MAX_USERNAME_LEN);
	body->peer_username[MAX_USERNAME_LEN] = '\0';
	bool res = proto_send_sign(ctx, msg, msglen);
	OPENSSL_free(msg);
	return res;
}

bool proto_run_dh(PROTO_CTX *ctx)
{
	assert(ctx);
	size_t msglen;
	struct dhkey *peer = (struct dhkey *)recv_message(ctx, DHKEY, &msglen, proto_recv_verify);
	if (!peer)
		return false;
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
	my->nonce = peer->nonce;
	my->len = pklen;
	memcpy(my->key, pk, pklen);
	OPENSSL_free(pk);
	if (!proto_send_sign(ctx, msg, MSG_SIZE_OF(struct dhkey) + pklen)) {
		OPENSSL_free(msg);
		dh_ctx_free(dhctx);
		return false;
	}
	OPENSSL_free(msg);
	unsigned char *secret = dh_derive_secret(dhctx, peer->key, peer->len);
	if (secret)
		proto_ctx_set_secret(ctx, secret);
	dh_ctx_free(dhctx);
	return !!secret;
}
