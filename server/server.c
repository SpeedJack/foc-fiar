#include "server/proto.h"
#include "error.h"
#include "memdbg.h"
#include "net.h"
#include "pem.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	memdbg_enable_debug();
	error_enable_autoprint();
	X509* cert = pem_read_x509_file("server_cert.pem");
	if (!cert)
		return 1;
	EVP_PKEY *privkey = pem_read_privkey("server_privkey.pem", NULL);
	if (!privkey)
		return 1;
	int sock = net_listen(8888, SOCK_STREAM);
	if (sock == -1)
		return 1;
	int conn = net_accept(sock);
	if (conn == -1)
		return 1;
	PROTO_CTX *ctx = proto_ctx_new(conn, NULL, privkey, NULL);
	if (!ctx)
		return 1;
	struct client_hello *hello = proto_recv_hello(ctx);
	if (!hello) {
		proto_clear_last_error();
		return 1;
	}
	printf("username: %s\n", hello->username);
	int len = strlen(hello->username);
	char *filename = OPENSSL_malloc(len + 5);
	strcpy(filename, hello->username);
	strcpy(filename + len, ".pem");
	EVP_PKEY *peerkey = pem_read_pubkey(filename);
	OPENSSL_free(filename);
	if (!peerkey)
		return 1;
	proto_ctx_set_peerkey(ctx, peerkey);
	if (!proto_verify_last_msg(ctx))
		return 1;
	if (!proto_send_cert(ctx, cert))
		return 1;
	X509_free(cert);
	if (!proto_send_hello(ctx, hello->username, hello->nonce))
		return 1;
	OPENSSL_free(hello);
	if (!proto_run_dh(ctx))
		return 1;
	char *dummymsg = "The quick brown fox jumps over a lazy dog. The quick brown fox jumps over a lazy dog.";
	if (!proto_send_gcm(ctx, dummymsg, strlen(dummymsg) + 1))
		return 1;
	size_t msglen;
	char *buf = (char *)proto_recv_gcm(ctx, &msglen);
	if (!buf)
		return 1;
	printf("Message: %s\nLen: %lu\n", buf, msglen);
	proto_ctx_free(ctx);
	net_close(sock);
	return 0;
}
