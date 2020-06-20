#ifdef HAVE_CONFIG_H
#include <config.h>
#else
#define PACKAGE_STRING	"connect-4 1.0.0"
#endif /* HAVE_CONFIG_H */

#include "client/cin.h"
#include "client/connect4.h"
#include "client/proto.h"
#include "cout.h"
#include "error.h"
#include "net.h"
#include "pem.h"
#include "random.h"
#include "stringop.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>

#define USAGE_STRING	\
	"Usage: %s [-h] [-v] [-i <num>] [-H <host>] [-p <port>] [-l <port>]"

/* Prints an error and exits with EXIT_FAILURE. */
static void panic(const char *errstr)
{
	cout_print_error(errstr);
	exit(EXIT_FAILURE);
}

/* Formats and prints an error, then it exits with EXIT_FAILURE. */
static void panicf(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	cout_vprintf_error(format, args);
	exit(EXIT_FAILURE);
}

/* Prints help message and exits. */
static inline void print_help(const char *cmdname)
{
	printf(USAGE_STRING "\n\n"
		"-h:\tprints this message and exits\n"
		"-v:\tprints version infos and exits\n"
		"-i:\tforce a specific IP protocol version (4 or 6)\n"
		"-H:\tspecifies the server hostname/address\n"
		"-p:\tspecifies the server port\n"
		"-l:\tspecifies the p2p listening port\n",
		cmdname);
}

/* Prints package name and version, then exits. */
static inline void print_version()
{
	puts(PACKAGE_STRING " (client)");
}

static int pass_cb(char *buf, int size, int rwflag, void *u)
{
	char *tmp = "password";
	size_t len = strlen(tmp);
	memcpy(buf, tmp, len);
	return len;
}

static void test(void)
{
	EVP_PKEY *privkey = pem_read_privkey("client_privkey.pem", pass_cb);
	if (!privkey) {
		error_print();
		return;
	}
	struct addrinfo *serveraddr = net_getaddrinfo("127.0.0.1", "8888", AF_INET, SOCK_STREAM);
	if (!serveraddr) {
		error_print();
		return;
	}
	int sock = net_connect(*serveraddr);
	if (sock == -1) {
		error_print();
		return;
	}
	PROTO_CTX *ctx = proto_ctx_new(sock, serveraddr, privkey, NULL);
	if (!ctx) {
		error_print();
		return;
	}
	uint32_t nonce = random_nonce();
	if (!proto_send_hello(ctx, "Alice", 5656, nonce)) {
		error_print();
		return;
	}
	X509 *cert = proto_recv_cert(ctx);
	if (!cert) {
		error_print();
		return;
	}
	X509 *ca = pem_read_x509_file("ca.pem");
	if (!ca) {
		error_print();
		return;
	}
	X509_CRL *crl = x509_read_crl("crl.pem");
	if (!crl) {
		error_print();
		return;
	}
	if (!x509_verify(cert, ca, crl)) {
		error_print();
		return;
	}
	struct server_hello *hello = proto_recv_hello(ctx);
	if (!hello) {
		error_print();
		return;
	}
	if (hello->nonce != nonce) {
		cout_print_error("Invalid nonce in SERVER_HELLO.");
		return;
	}
	if (!proto_run_dh(ctx)) {
		error_print();
		return;
	}
	size_t len;
	char *buf = (char *)proto_recv_gcm(ctx, &len);
	if (buf) {
		error_print();
		return;
	}
	printf("Message: %s\nLen: %lu\n", buf, len);
	OPENSSL_free(buf);
	proto_ctx_free(ctx);
}

/* Client entry-point. */
int main(int argc, char **argv)
{
	test();
	return 0;
#ifdef DEBUG_CODE
	//cout_enable_mem_debug();
#endif /* DEBUG_CODE */
	char *tmp = OPENSSL_malloc(20);
	tmp[0] = 5;
	tmp[1] = 10;
	OPENSSL_free(tmp);
	return 0;
	uint16_t server_port = 55555;
	uint16_t listening_port = 50505;
	char server_addr[254] = "";
	int force_ipv = 0;
	int opt;

	while ((opt = getopt(argc, argv, "+:hvi:H:p:l:")) != -1)
		switch (opt) {
		case 'h':
			print_help(argv[0]);
			return 0;
		case 'v':
			print_version();
			return 0;
		case 'i':
			if (!string_to_int(optarg, &force_ipv)
					|| (force_ipv != 4 && force_ipv != 6))
				panicf("Invalid option argument for -i: %s.",
					optarg);
			break;
		case 'H':
			strncpy(server_addr, optarg, 254);
			if (server_addr[253] != '\0')
				panic("Server address is too long.");
			break;
		case 'p':
			if (!string_to_uint16(optarg, &server_port))
				panicf("Invalid port number %s. Enter a value between 0 and 65535.",
					optarg);
			break;
		case 'l':
			if (!string_to_uint16(optarg, &listening_port))
				panicf("Invalid port number %s. Enter a value between 0 and 65535.",
					optarg);
			break;
		default:
			panicf("Invalid option: %c.\n" USAGE_STRING,
				optopt, argv[0]);
		}

	if (optind < argc)
		panicf("Invalid argument: %s.\n" USAGE_STRING,
			argv[optind], argv[0]);

	printf("force_ipv = %d\n"
		"server_addr = %s\n"
		"server_port = %hu\n"
		"listening_port = %hu\n",
		force_ipv, server_addr, server_port, listening_port);

	return 0;
}
