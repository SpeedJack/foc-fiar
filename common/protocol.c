#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "protocol.h"
#include "assertions.h"
#include "digest.h"
#include "error.h"
#include "gcm.h"
#include "memdbg.h"
#include "net.h"
#include "random.h"
#include <string.h>

struct __attribute__((packed)) msg_header {
	uint32_t magic;
	uint32_t counter;
	uint32_t ack_msg;
	uint32_t payload_size;
	uint32_t nonce;
};

struct __attribute__((packed)) msg {
	struct msg_header header;
	unsigned char payload[];
};

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
	struct msg *last_recv_msg;
};

typedef void *transform_cb(PROTO_CTX *ctx, const void *data, size_t len,
	size_t *outlen);
typedef struct msg *(recv_fn)(PROTO_CTX *ctx, size_t *len);

#define FIRST_MSG_SIZE		54
#define FIRST_PL_SIZE		(FIRST_MSG_SIZE - sizeof(struct msg_header))
#define REMAINING_SIZE(total)	(total - FIRST_PL_SIZE + sizeof(struct msg_header))
#define MAX_PL_SIZE		(1<<26)
#define MAX_SIG_SIZE		MAX_PL_SIZE

#define RECV_MODE_PLAIN		0
#define RECV_MODE_SIGNED	1
#define RECV_MODE_ENCRYPTED	2

PROTO_CTX *proto_ctx_new(int socket, struct addrinfo *peeraddr,
	EVP_PKEY *privkey, EVP_PKEY *peerkey)
{
	PROTO_CTX *ctx = OPENSSL_malloc(sizeof(PROTO_CTX));
	if (!ctx) {
		REPORT_ERR(EALLOC, "Can not allocate space for PROTO_CTX.");
		return NULL;
	}
	ctx->socket = socket;
	ctx->peeraddr = peeraddr;
	ctx->dctx = digest_ctx_new(privkey, peerkey);
	ctx->gctx = NULL;
	ctx->send_counter = 0;
	ctx->recv_counter = 0;
	ctx->last_ack = 0;
	ctx->last_recv_nonce = 0;
	ctx->last_send_nonce = 0;
	ctx->last_recv_msg = NULL;
	return ctx;
}

void proto_ctx_set_peerkey(PROTO_CTX *ctx, EVP_PKEY *peerkey)
{
	assert(ctx && ctx->dctx);
	digest_ctx_set_peerkey(ctx->dctx, peerkey);
}

void proto_ctx_set_secret(PROTO_CTX *ctx, const unsigned char *secret)
{
	ctx->gctx = gcm_ctx_new(secret);
}

void proto_clear_last_recv_msg(PROTO_CTX *ctx)
{
	if (!ctx->last_recv_msg)
		return;
	OPENSSL_clear_free(ctx->last_recv_msg,
		ctx->last_recv_msg->header.payload_size + sizeof(struct msg_header));
	ctx->last_recv_msg = NULL;
}

void proto_ctx_free(PROTO_CTX *ctx)
{
	if (!ctx)
		return;
	proto_clear_last_recv_msg(ctx);
	digest_ctx_free(ctx->dctx);
	gcm_ctx_free(ctx->gctx);
	net_close(ctx->socket);
	freeaddrinfo(ctx->peeraddr);
	OPENSSL_free(ctx);
}

static struct msg_header create_header(PROTO_CTX *ctx, size_t len, uint32_t nonce)
{
	assert(ctx);
	ctx->last_send_nonce = nonce;
	ctx->send_counter++;
	struct msg_header header = { MAGIC_NUMBER, ctx->send_counter,
		ctx->recv_counter, len, ctx->last_send_nonce };
	return header;
}

static struct msg *craft_msg(PROTO_CTX *ctx, const unsigned char *data, size_t len,
	size_t *outlen, struct msg **second)
{
	assert(ctx && outlen);
	uint32_t nonce = random_nonce();
	if (nonce == 0)
		return NULL;
	*outlen = !second ? len + sizeof(struct msg_header)
		: (FIRST_MSG_SIZE + (len > FIRST_PL_SIZE
					? REMAINING_SIZE(len) : 0));
	struct msg *msg = OPENSSL_zalloc(*outlen);
	if (!msg) {
		REPORT_ERR(EALLOC, "Can not allocate space for the messages to be sent.");
		return NULL;
	}
	struct msg_header header = create_header(ctx, len, nonce);
	memcpy(msg, &header, sizeof(struct msg_header));
	if (data) {
		assert(len > 0);
		memcpy((char *)msg + sizeof(struct msg_header), data,
			(second && len > FIRST_PL_SIZE) ? FIRST_PL_SIZE : len);
	}
	if (second && len > FIRST_PL_SIZE) {
		*second = (struct msg *)(((char *)msg) + FIRST_MSG_SIZE);
		nonce = random_nonce();
		if (nonce == 0) {
			OPENSSL_clear_free(msg, FIRST_MSG_SIZE);
			return NULL;
		}
		header = create_header(ctx, len - FIRST_PL_SIZE, nonce);
		memcpy(*second, &header, sizeof(struct msg_header));
		memcpy((char *)(*second) + sizeof(struct msg_header),
			data + FIRST_PL_SIZE, len - FIRST_PL_SIZE);
	}
	return msg;
}

static void *encrypt_single_msg(PROTO_CTX *ctx, const struct msg *msg,
	size_t len, size_t *outlen)
{
	unsigned char tag[16];
	unsigned char *ct = gcm_encrypt(ctx->gctx, (unsigned char *)msg, len, tag);
	if (!ct)
		return NULL;
	*outlen = len + sizeof(tag);
	unsigned char *buf = OPENSSL_malloc(*outlen);
	if (!buf) {
		REPORT_ERR(EALLOC, "Can not allocate space for the encrypted message to be sent.");
		OPENSSL_free(ct);
		return NULL;
	}
	memcpy(buf, ct, len);
	memcpy(buf + len, tag, sizeof(tag));
	OPENSSL_free(ct);
	return buf;
}

static void *encrypt_msg(PROTO_CTX *ctx, const void *data, size_t len,
	size_t *outlen)
{
	assert(ctx && ctx->gctx && data && outlen);
	struct msg *second = NULL;
	struct msg *msg = craft_msg(ctx, (unsigned char *)data, len, outlen, &second);
	if (!msg)
		return NULL;
	size_t firstsize;
	unsigned char *ct = encrypt_single_msg(ctx, msg, FIRST_MSG_SIZE, &firstsize);
	if (!ct) {
		OPENSSL_clear_free(msg, *outlen);
		return NULL;
	}
	size_t secondsize = 0;
	unsigned char *nextct = NULL;
	if (second) {
		nextct = encrypt_single_msg(ctx, (struct msg *)(((char *)msg) + FIRST_MSG_SIZE),
			*outlen - FIRST_MSG_SIZE, &secondsize);
		if (!nextct) {
			OPENSSL_free(ct);
			OPENSSL_clear_free(msg, *outlen);
			return NULL;
		}
	}
	OPENSSL_clear_free(msg, *outlen);
	*outlen = firstsize + secondsize;
	unsigned char *buf = OPENSSL_malloc(*outlen);
	if (!buf) {
		REPORT_ERR(EALLOC, "Can not allocate space for the encrypted messages to be sent.");
		OPENSSL_free(ct);
		OPENSSL_free(nextct);
		return NULL;
	}
	memcpy(buf, ct, firstsize);
	OPENSSL_free(ct);
	if (nextct) {
		memcpy(buf + firstsize, nextct, secondsize);
		OPENSSL_free(nextct);
	}
	return buf;
}

static void *sign_msg(PROTO_CTX *ctx, const void *data, size_t len,
	size_t *outlen)
{
	assert(ctx && ctx->dctx && data && outlen);
	size_t msglen;
	struct msg *msg = craft_msg(ctx, (unsigned char *)data, len, &msglen, NULL);
	if (!msg)
		return NULL;
	size_t slen;
	unsigned char* sig = digest_sign(ctx->dctx, (unsigned char *)msg,
		msglen, &slen);
	if (!sig) {
		OPENSSL_free(msg);
		return NULL;
	}
	assert(slen > 0);
	uint32_t siglen = (uint32_t)slen;
	*outlen = msglen + sizeof(uint32_t) + slen;
	unsigned char *buf = OPENSSL_malloc(*outlen);
	if (!buf) {
		REPORT_ERR(EALLOC, "Can not allocate space for the signed message to be sent.");
		OPENSSL_free(msg);
		OPENSSL_free(sig);
		return NULL;
	}
	memcpy(buf, msg, msglen);
	memcpy(buf + msglen, &siglen, sizeof(uint32_t));
	memcpy(buf + msglen + sizeof(uint32_t), sig, slen);
	OPENSSL_free(msg);
	OPENSSL_free(sig);
	return buf;
}

static void *plain_msg(PROTO_CTX *ctx, const void *data, size_t len,
	size_t *outlen)
{
	return craft_msg(ctx, (unsigned char *)data, len, outlen, NULL);
}

static bool send_msg(PROTO_CTX *ctx, const void *data, size_t len,
	transform_cb *transform)
{
	assert(ctx && data && transform);
	size_t outlen;
	void *msg = transform(ctx, data, len, &outlen);
	if (!msg)
		return false;
	assert(outlen > len);
	if (!net_send(ctx->socket, msg, outlen, ctx->peeraddr)) {
		OPENSSL_clear_free(msg, outlen);
		return false;
	}
	memdbg_dump("MESSAGE SENT", msg, outlen);
	OPENSSL_clear_free(msg, outlen);
	return true;
}

bool proto_send(PROTO_CTX *ctx, const void *data, size_t len)
{
	return send_msg(ctx, data, len, plain_msg);
}

bool proto_send_sign(PROTO_CTX *ctx, const void *data, size_t len)
{
	return send_msg(ctx, data, len, sign_msg);
}

bool proto_send_gcm(PROTO_CTX *ctx, const void *data, size_t len)
{
	assert(ctx && ctx->gctx);
	gcm_ctx_set_nonce(ctx->gctx, ctx->last_recv_nonce);
	return send_msg(ctx, data, len, encrypt_msg);
}

static bool valid_header(PROTO_CTX *ctx, struct msg_header header)
{
	assert(ctx);
	if (header.magic != MAGIC_NUMBER) {
		REPORT_ERR(EINVMSG, "Invalid magic number.");
		goto return_error;
	}
	if (header.counter <= ctx->recv_counter) {
		REPORT_ERR(EREPLAY, NULL);
		goto return_error;
	}
	ctx->recv_counter = header.counter;
	if (header.ack_msg > ctx->send_counter) {
		REPORT_ERR(EINVACK, NULL);
		goto return_error;
	}
	if (header.payload_size > MAX_PL_SIZE) {
		REPORT_ERR(ETOOBIG, "Received a message with a too long payload.");
		goto return_error;
	}
	ctx->last_ack = header.ack_msg;
	ctx->last_recv_nonce = header.nonce;
	return true;
return_error:
	memdbg_dump("INVALID HEADER RECEIVED", &header, sizeof(struct msg_header));
	return false;
}

static unsigned char *recv_signature(PROTO_CTX *ctx, uint32_t *len)
{
	assert(ctx && len);
	if (!net_recv(ctx->socket, len, sizeof(uint32_t)))
		return NULL;
	if (*len > MAX_SIG_SIZE) {
		REPORT_ERR(ETOOBIG, "Received a message with a too long signature.");
		return NULL;
	}
	unsigned char *sig = OPENSSL_malloc(*len);
	if (!sig) {
		REPORT_ERR(EALLOC, "Can not allocate space for message signature.");
		return NULL;
	}
	if (!net_recv(ctx->socket, sig, *len)) {
		OPENSSL_free(sig);
		return NULL;
	}
	memdbg_dump("SIGNATURE RECEIVED", sig, *len);
	return sig;
}

bool proto_verify_last_msg(PROTO_CTX *ctx)
{
	uint32_t len;
	unsigned char *sig = recv_signature(ctx, &len);
	if (!sig)
		return false;
	bool res = digest_verify(ctx->dctx, (unsigned char *)ctx->last_recv_msg,
		ctx->last_recv_msg->header.payload_size + sizeof(struct msg_header),
		sig, len);
	if (!res && error_get() == ENOERR)
		REPORT_ERR(EINVSIG, NULL);
	OPENSSL_free(sig);
	return res;
}

static void *decrypt_msg(PROTO_CTX *ctx, const void *data, size_t len,
	size_t *outlen)
{
	assert(ctx && ctx->gctx && data && outlen);
	unsigned char tag[16];
	if (!net_recv(ctx->socket, tag, sizeof(tag)))
		return NULL;
	memdbg_dump("GCM TAG RECEIVED", tag, sizeof(tag));
	gcm_ctx_set_nonce(ctx->gctx, ctx->last_send_nonce);
	struct msg *msg = (struct msg *)gcm_decrypt(ctx->gctx,
		(unsigned char *)data, len, tag);
	*outlen = len;
	return msg;
}

static struct msg_header *recv_msg_header(PROTO_CTX *ctx)
{
	assert(ctx);
	struct msg_header *header = OPENSSL_malloc(sizeof(struct msg_header));
	if (!header) {
		REPORT_ERR(EALLOC, "Can not allocate space for the incoming message header.");
		return NULL;
	}
	if (!net_recv(ctx->socket, header, sizeof(struct msg_header))) {
		OPENSSL_free(header);
		return NULL;
	}
	if (!valid_header(ctx, *header)) {
		OPENSSL_free(header);
		return NULL;
	}
	return header;
}

static struct msg *recv_single_encrypted_msg(PROTO_CTX *ctx, size_t len)
{
	void *encrypted = OPENSSL_malloc(len);
	if (!encrypted) {
		REPORT_ERR(EALLOC, "Can not allocate space for the incoming encrypted message.");
		return NULL;
	}
	if (!net_recv(ctx->socket, encrypted, len)) {
		OPENSSL_free(encrypted);
		return NULL;
	}
	memdbg_dump("ENCRYPTED MESSAGE RECEIVED", encrypted, len);
	size_t outlen;
	struct msg *msg = decrypt_msg(ctx, encrypted, len, &outlen);
	OPENSSL_free(encrypted);
	if (!msg)
		return NULL;
	memdbg_dump("DECRYPTED MESSAGE", msg, outlen);
	assert(outlen == len);
	if (!valid_header(ctx, msg->header)) {
		OPENSSL_clear_free(msg, outlen);
		return NULL;
	}
	return msg;
}

static struct msg *recv_encrypted_msg(PROTO_CTX *ctx, size_t *len)
{
	assert(ctx && len);
	struct msg *msg = recv_single_encrypted_msg(ctx, FIRST_MSG_SIZE);
	if (!msg)
		return NULL;
	*len = msg->header.payload_size;
	struct msg *buf = OPENSSL_malloc(*len + sizeof(struct msg_header));
	if (!buf) {
		REPORT_ERR(EALLOC, "Can not allocate space for the incoming message.");
		OPENSSL_clear_free(msg, FIRST_MSG_SIZE);
		return NULL;
	}
	memcpy(buf, msg, *len > FIRST_PL_SIZE ? FIRST_MSG_SIZE : *len + sizeof(struct msg_header));
	OPENSSL_clear_free(msg, FIRST_MSG_SIZE);
	if (*len > FIRST_PL_SIZE) {
		msg = recv_single_encrypted_msg(ctx, REMAINING_SIZE(*len));
		if (!msg) {
			OPENSSL_clear_free(buf, FIRST_MSG_SIZE);
			return NULL;
		}
		assert(msg->header.payload_size == *len - FIRST_PL_SIZE);
		memcpy((char *)buf + FIRST_MSG_SIZE, msg->payload, *len - FIRST_PL_SIZE);
		OPENSSL_clear_free(msg, REMAINING_SIZE(*len));
	}
	return buf;
}

static struct msg *recv_msg(PROTO_CTX *ctx, size_t *len)
{
	assert(ctx && len);
	struct msg_header *header = recv_msg_header(ctx);
	if (!header)
		return NULL;
	*len = header->payload_size;
	struct msg *msg = OPENSSL_malloc(*len + sizeof(struct msg_header));
	if (!msg) {
		REPORT_ERR(EALLOC, "Can not allocate space for the incoming message.");
		OPENSSL_free(header);
		return NULL;
	}
	memcpy(&msg->header, header, sizeof(struct msg_header));
	OPENSSL_free(header);
	if (!net_recv(ctx->socket, msg->payload, *len)) {
		OPENSSL_clear_free(msg, *len + sizeof(struct msg_header));
		return NULL;
	}
	memdbg_dump("MESSAGE RECEIVED", msg, *len + sizeof(struct msg_header));
	return msg;
}

static void *real_recv(PROTO_CTX *ctx, size_t *len, int mode)
{
	proto_clear_last_recv_msg(ctx);
	recv_fn *recv_impl = mode == RECV_MODE_ENCRYPTED
		? &recv_encrypted_msg : &recv_msg;
	struct msg *msg = recv_impl(ctx, len);
	if (!msg)
		return NULL;
	ctx->last_recv_msg = msg;
	if (mode == RECV_MODE_SIGNED && !proto_verify_last_msg(ctx))
		return NULL;
	return msg->payload;
}

void *proto_recv(PROTO_CTX *ctx, size_t *len)
{
	return real_recv(ctx, len, RECV_MODE_PLAIN);
}

void *proto_recv_verify(PROTO_CTX *ctx, size_t *len)
{
	return real_recv(ctx, len, RECV_MODE_SIGNED);
}

void *proto_recv_gcm(PROTO_CTX *ctx, size_t *len)
{
	return real_recv(ctx, len, RECV_MODE_ENCRYPTED);
}
