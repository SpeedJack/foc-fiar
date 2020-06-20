#include "server/proto.h"
#include "cout.h"
#include "error.h"
#include "net.h"
#include "pem.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	X509* cert = pem_read_x509_file("server_cert.pem");
	if (!cert) {
		error_print();
		return 1;
	}
	EVP_PKEY *privkey = pem_read_privkey("server_privkey.pem", NULL);
	if (!privkey) {
		error_print();
		return 1;
	}
	int sock = net_listen(8888, SOCK_STREAM);
	if (sock == -1) {
		error_print();
		return 1;
	}
	int conn = net_accept(sock);
	if (conn == -1) {
		error_print();
		return 1;
	}
	PROTO_CTX *ctx = proto_ctx_new(conn, NULL, privkey, NULL);
	if (!ctx) {
		error_print();
		return 1;
	}
	struct client_hello *hello = proto_recv_hello(ctx);
	if (!hello) {
		error_print();
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
	if (!peerkey) {
		error_print();
		return 1;
	}
	proto_ctx_set_peerkey(ctx, peerkey);
	if (!proto_verify_last_msg(ctx)) {
		error_print();
		return 1;
	}
	if (!proto_send_cert(ctx, cert)) {
		error_print();
		return 1;
	}
	if (!proto_send_hello(ctx, hello->username, hello->nonce)) {
		error_print();
		return 1;
	}
	if (!proto_run_dh(ctx)) {
		error_print();
		return 1;
	}
	char *dummymsg = "msg msg msg";
	if (!proto_send_gcm(ctx, dummymsg, strlen(dummymsg) + 1)) {
		error_print();
		return 1;
	}
	proto_ctx_free(ctx);
	return 0;
}
