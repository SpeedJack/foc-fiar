#include "proto.h"
#include "dh.h"
#include "digest.h"
#include "error.h"
#include "gcm.h"
#include "net.h"
#include "random.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

struct proto_ctx {
	int socket;
	struct addrinfo *peeraddr;
	DIGEST_CTX *dctx;
	GCM_CTX *gctx;
	unsigned int send_counter;
	unsigned int recv_counter;
	unsigned int last_ack;
	uint32_t last_recv_nonce;
	uint32_t last_send_nonce;
};

struct __attribute__((packed)) msg_header {
	uint32_t counter;
	uint32_t ack_msg;
	uint32_t payload_size;
	uint32_t nonce;
};

struct __attribute__((packed)) msg {
	struct msg_header header;
	unsigned char payload[];
};

typedef void *transform_cb(PROTO_CTX *ctx, const void *data, size_t len, size_t *outlen);

#define FIRST_MSG_SIZE		128
#define FIRST_PL_SIZE		(FIRST_MSG_SIZE - sizeof(struct msg_header))
#define REMAINING_SIZE(total)	(total - FIRST_PL_SIZE + sizeof(struct msg_header))

PROTO_CTX *proto_ctx_new(int socket, struct addrinfo *peeraddr, EVP_PKEY *privkey, EVP_PKEY *pubkey)
{
	PROTO_CTX *ctx = malloc(sizeof(PROTO_CTX));
	if (!ctx) {
		REPORT_ERR(EALLOC, "Can not allocate space for PROTO_CTX.");
		return NULL;
	}
	ctx->socket = socket;
	ctx->peeraddr = peeraddr;
	ctx->dctx = digest_ctx_new(privkey, pubkey);
	ctx->gctx = NULL;
	ctx->send_counter = 0;
	ctx->recv_counter = 0;
	ctx->last_ack = 0;
	ctx->last_recv_nonce = 0;
	ctx->last_send_nonce = 0;
	return ctx;
}

void proto_ctx_free(PROTO_CTX *ctx)
{
	if (!ctx)
		return;
	digest_ctx_free(ctx->dctx);
	gcm_ctx_free(ctx->gctx);
	free(ctx);
}

static struct msg_header create_header(PROTO_CTX *ctx, size_t len)
{
	assert(ctx);
	ctx->last_send_nonce = random_nonce();
	ctx->send_counter++;
	struct msg_header header = { ctx->send_counter, ctx->recv_counter, len, ctx->last_send_nonce };
	return header;
}

static void *craft_msg(PROTO_CTX *ctx, const void *data, size_t len, size_t *outlen)
{
	assert(ctx && outlen);
	*outlen = FIRST_MSG_SIZE + (len > FIRST_PL_SIZE ? REMAINING_SIZE(len) : 0);
	void *msg = calloc(*outlen, 1);
	if (!msg) {
		REPORT_ERR(EALLOC, "Can not allocate space for the messages to be sent.");
		return NULL;
	}
	struct msg_header header = create_header(ctx, len);
	memcpy(msg, &header, sizeof(struct msg_header));
	if (data) {
		assert(len > 0);
		memcpy(msg + sizeof(struct msg_header), data, len > FIRST_PL_SIZE ? FIRST_PL_SIZE : len);
	}
	if (len > FIRST_PL_SIZE) {
		void *secondptr = msg + FIRST_MSG_SIZE;
		header = create_header(ctx, len - FIRST_PL_SIZE);
		memcpy(secondptr, &header, sizeof(struct msg_header));
		memcpy(secondptr + sizeof(struct msg_header), data + FIRST_PL_SIZE, len - FIRST_PL_SIZE);
	}
	return msg;
}

static void *encrypt_single_msg(PROTO_CTX *ctx, const void *data, size_t len, size_t *outlen)
{
	assert(ctx && ctx->gctx && data && outlen);
	unsigned char tag[16];
	unsigned char *ct = gcm_encrypt(ctx->gctx, (unsigned char *)data, len, tag);
	if (!ct)
		return NULL;
	*outlen = len + sizeof(tag);
	void *msg = malloc(*outlen);
	if (!msg) {
		REPORT_ERR(EALLOC, "Can not allocate space for the encrypted message to be sent.");
		free(msg);
		return NULL;
	}
	memcpy(msg, ct, len);
	memcpy(msg + len, tag, sizeof(tag));
	free(ct);
	return msg;
}

static void *sign_single_msg(PROTO_CTX *ctx, const void *data, size_t len, size_t *outlen)
{
	assert(ctx && ctx->dctx && data && outlen);
	size_t slen;
	unsigned char* sig = digest_sign(ctx->dctx, (unsigned char *)data, len, &slen);
	if (!sig)
		return NULL;
	assert(slen > 0);
	uint32_t siglen = (uint32_t)slen;
	*outlen = len + sizeof(uint32_t) + slen;
	void *msg = malloc(*outlen);
	if (!msg) {
		REPORT_ERR(EALLOC, "Can not allocate space for the signed message to be sent.");
		free(sig);
		return NULL;
	}
	memcpy(msg, data, len);
	memcpy(msg + len, &siglen, sizeof(uint32_t));
	memcpy(msg + len + sizeof(uint32_t), sig, slen);
	free(sig);
	return msg;
}

static void *transform_msg(PROTO_CTX *ctx, const void *data, size_t len,
	size_t *outlen, transform_cb *transform)
{
	assert(ctx && data && transform && outlen);
	size_t msglen;
	void *msg = craft_msg(ctx, data, len, &msglen);
	assert(msglen > len);
	if (!msg)
		return NULL;
	size_t flen;
	void *first = transform(ctx, msg, FIRST_MSG_SIZE, &flen);
	if (!first) {
		free(msg);
		return NULL;
	}
	assert(flen >= FIRST_MSG_SIZE);
	void *second = NULL;
	size_t slen = 0;
	if (msglen > FIRST_MSG_SIZE) {
		second = transform(ctx, msg + FIRST_MSG_SIZE, msglen - FIRST_MSG_SIZE, &slen);
		if (!second) {
			free(msg);
			free(first);
			return NULL;
		}
		assert(slen >= msglen - FIRST_MSG_SIZE);
	}
	free(msg);
	*outlen = flen + slen;
	void *result = malloc(*outlen);
	if (!result) {
		REPORT_ERR(EALLOC, "Can not allocate space for the messages to be sent.");
		free(first);
		free(second);
		return NULL;
	}
	memcpy(result, first, flen);
	if (second)
		memcpy(result + flen, second, slen);
	free(first);
	free(second);
	return result;
}

static void *encrypt_msg(PROTO_CTX *ctx, const void *data, size_t len, size_t *outlen)
{
	assert(ctx && ctx->dctx);
	gcm_ctx_set_nonce(ctx->gctx, ctx->last_recv_nonce);
	return transform_msg(ctx, data, len, outlen, encrypt_single_msg);
}


static void *sign_msg(PROTO_CTX *ctx, const void *data, size_t len, size_t *outlen)
{
	return transform_msg(ctx, data, len, outlen, sign_single_msg);
}

static bool send_msg(PROTO_CTX *ctx, const void *data, size_t len, transform_cb *transform)
{
	assert(ctx && data && transform);
	size_t outlen;
	void *msg = transform(ctx, data, len, &outlen);
	if (!msg)
		return false;
	assert(outlen > len);
	if (!net_sendto(ctx->socket, msg, outlen, 0, ctx->peeraddr)) {
		free(msg);
		return false;
	}
	free(msg);
	return true;
}

bool proto_send(PROTO_CTX *ctx, const void *data, size_t len)
{
	return send_msg(ctx, data, len, craft_msg);
}

bool proto_send_sign(PROTO_CTX *ctx, const void *data, size_t len)
{
	return send_msg(ctx, data, len, sign_msg);
}

bool proto_send_gcm(PROTO_CTX *ctx, const void *data, size_t len)
{
	return send_msg(ctx, data, len, encrypt_msg);
}

static bool valid_header(PROTO_CTX *ctx, struct msg_header header)
{
	assert(ctx);
	if (header.counter <= ctx->recv_counter) {
		REPORT_ERR(EREPLAY, NULL);
		return false;
	}
	ctx->recv_counter = header.counter;
	if (header.ack_msg > ctx->send_counter) {
		REPORT_ERR(EINVACK, NULL);
		return false;
	}
	ctx->last_ack = header.ack_msg;
	ctx->last_recv_nonce = header.nonce;
	return true;
}

static void *verify_msg(PROTO_CTX *ctx, const void *data, size_t len, size_t *outlen)
{
	assert(ctx && ctx->dctx && data && outlen);
	uint32_t siglen;
	if (!net_recv(ctx->socket, &siglen, sizeof(uint32_t), 0))
		return NULL;
	unsigned char sig[siglen];
	if (!net_recv(ctx->socket, sig, siglen, 0))
		return NULL;
	if (!digest_verify(ctx->dctx, (unsigned char *)data, len, sig, siglen)) {
		REPORT_ERR(EINVSIG, NULL);
		return NULL;
	}
	*outlen = len;
	void *msg = malloc(len);
	if (!msg) {
		REPORT_ERR(EALLOC, "Can not allocate space for the verified signed message.");
		return NULL;
	}
	memcpy(msg, data, len);
	return msg;

}

static void *decrypt_msg(PROTO_CTX *ctx, const void *data, size_t len, size_t *outlen)
{
	assert(ctx && ctx->gctx && data && outlen);
	unsigned char tag[16];
	if (!net_recv(ctx->socket, tag, sizeof(tag), 0))
		return NULL;
	gcm_ctx_set_nonce(ctx->gctx, ctx->last_send_nonce);
	struct msg *msg = (struct msg *)gcm_decrypt(ctx->gctx, (unsigned char *)data, len, tag);
	*outlen = len;
	return msg;
}

static void *recv_single_msg(PROTO_CTX *ctx, size_t len, transform_cb *transform)
{
	assert(ctx);
	void *buf = malloc(len);
	if (!buf) {
		REPORT_ERR(EALLOC, "Can not allocate space for the incoming message.");
		return NULL;
	}
	if (!net_recv(ctx->socket, buf, len, 0)) {
		free(buf);
		return NULL;
	}
	struct msg *msg = buf;
	if (transform) {
		size_t outlen;
		msg = transform(ctx, buf, len, &outlen);
		free(buf);
		if (!msg)
			return NULL;
		assert(outlen == len);
	}
	if (!valid_header(ctx, msg->header)) {
		free(msg);
		return NULL;
	}
	ctx->last_recv_nonce = msg->header.nonce;
	return msg;
}

static void *recv_msg(PROTO_CTX *ctx, size_t *len, transform_cb *transform)
{
	assert(ctx && len);
	struct msg *msg = recv_single_msg(ctx, FIRST_MSG_SIZE, transform);
	if (!msg)
		return NULL;
	*len = msg->header.payload_size;
	void *result = malloc(*len);
	if (!result) {
		REPORT_ERR(EALLOC, "Can not allocate space for the incoming message.");
		free(msg);
		return NULL;
	}
	memcpy(result, msg->payload, FIRST_PL_SIZE);
	free(msg);
	if (*len <= FIRST_PL_SIZE)
		return result;
	assert(REMAINING_SIZE(*len) > 0);
	msg = recv_single_msg(ctx, REMAINING_SIZE(*len), transform);
	assert(*len == msg->header.payload_size + FIRST_PL_SIZE);
	memcpy(result + FIRST_PL_SIZE, msg->payload, msg->header.payload_size);
	free(msg);
	return result;
}

void *proto_recv(PROTO_CTX *ctx, size_t *len)
{
	return recv_msg(ctx, len, NULL);
}

void *proto_recv_sign(PROTO_CTX *ctx, size_t *len)
{
	return recv_msg(ctx, len, verify_msg);
}

void *proto_recv_gcm(PROTO_CTX *ctx, size_t *len)
{
	return recv_msg(ctx, len, decrypt_msg);
}

bool proto_run_dh(PROTO_CTX *ctx)
{
	assert(ctx);
	DH_CTX *dhctx = dh_ctx_new();
	size_t pklen;
	unsigned char *pk = dh_gen_pubkey(dhctx, &pklen);
	if (!pk || !proto_send_sign(ctx, pk, pklen))
		goto return_error;
	size_t peerlen;
	unsigned char *peerkey = proto_recv_sign(ctx, &peerlen);
	if (!peerkey)
		goto return_error;
	unsigned char *secret = dh_derive_secret(dhctx, peerkey, peerlen);
	free(peerkey);
	if (!secret)
		goto return_error;
	dh_ctx_free(dhctx);
	ctx->gctx = gcm_ctx_new(secret);
	return ctx->gctx != NULL;
return_error:
	dh_ctx_free(dhctx);
	return false;
}
