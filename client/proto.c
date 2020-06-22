#include "client/proto.h"
#include "assertions.h"
#include "dh.h"
#include "error.h"
#include "random.h"
#include <string.h>

typedef void *recv_func(PROTO_CTX *ctx, size_t *len);

static enum err_code last_error = NOERR;

enum err_code proto_get_last_error(void)
{
	return last_error;
}

static void *recv_message(PROTO_CTX *ctx, enum msg_type type, size_t *len,
	recv_func *recv)
{
	assert(ctx && recv);
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
		last_error = ((struct error *)msg)->code;
		REPORT_ERR(EPEERERR, ((struct error *)msg)->message);
		return NULL;
	}
	OPENSSL_clear_free(buf, msglen - sizeof(struct message));
	last_error = EINVMSG;
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

bool proto_send_error(PROTO_CTX *ctx, enum err_code code, const char *message)
{
	size_t msglen = MSG_SIZE_OF(struct client_hello) + strlen(message) + 1;
	struct message *msg = OPENSSL_zalloc(msglen);
	if (!msg) {
		REPORT_ERR(EALLOC, "Can not allocate space for ERROR message.");
		return false;
	}
	msg->type = ERROR;
	struct error *body = (struct error *)msg->body;
	body->code = code;
	strcpy(body->message, message);
	bool res = proto_send(ctx, msg, msglen); //TODO support for gcm/signed mode
	OPENSSL_free(msg);
	return res;
}

X509 *proto_recv_cert(PROTO_CTX *ctx)
{
	size_t msglen;
	struct server_cert *msg = recv_message(ctx, SERVER_CERT, &msglen, proto_recv);
	if (!msg)
		return NULL;
	X509* cert = x509_deserialize(msg->cert, (size_t)msg->len);
	OPENSSL_clear_free(msg, msglen);
	return cert;
}

struct server_hello *proto_recv_hello(PROTO_CTX *ctx)
{
	return (struct server_hello *)recv_message(ctx, SERVER_HELLO, NULL, proto_recv_verify);
}

bool proto_run_dh(PROTO_CTX *ctx)
{
	assert(ctx);
	uint32_t nonce = random_nonce();
	if (nonce == 0)
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
	my->nonce = nonce;
	my->len = (uint32_t)pklen;
	memcpy(my->key, pk, pklen);
	OPENSSL_clear_free(pk, pklen);
	if (!proto_send_sign(ctx, msg, MSG_SIZE_OF(struct dhkey) + pklen)) {
		OPENSSL_clear_free(msg, MSG_SIZE_OF(struct dhkey) + pklen);
		dh_ctx_free(dhctx);
		return false;
	}
	OPENSSL_clear_free(msg, MSG_SIZE_OF(struct dhkey) + pklen);
	size_t peerlen;
	struct dhkey *peer = (struct dhkey *)recv_message(ctx, DHKEY, &peerlen, proto_recv_verify);
	if (!peer) {
		dh_ctx_free(dhctx);
		return false;
	}
	if (peer->nonce != nonce) {
		REPORT_ERR(EINVMSG, "Received a signed message with a wrong nonce.");
		OPENSSL_clear_free(peer, peerlen);
		dh_ctx_free(dhctx);
		return false;
	}
	unsigned char *secret = dh_derive_secret(dhctx, peer->key, (size_t)peer->len);
	OPENSSL_clear_free(peer, peerlen);
	if (secret) {
		proto_ctx_set_secret(ctx, secret);
		memset(secret, 0, DH_SECRET_LENGTH);
	}
	dh_ctx_free(dhctx);
	return !!secret;
}
