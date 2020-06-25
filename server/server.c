#ifdef HAVE_CONFIG_H
#include <config.h>
#else
#define PACKAGE_STRING	"connect-4 1.0.0"
#endif /* HAVE_CONFIG_H */

#include "server/proto.h"
#include "cout.h"
#include "error.h"
#include "memdbg.h"
#include "net.h"
#include "pem.h"
#include "stringop.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define USAGE_STRING	\
	"Usage: %s [-h] [-v] [-p <port>] [-c <cert-file>] [-k <key-file>] [-d <userkeys-dir>]"

#define DEFAULT_PORT		8888
#define DEFAULT_CERT_FILE	"server_cert.pem"
#define DEFAULT_KEY_FILE	"server_privkey.pem"

static struct {
	uint16_t port;
	char cert_file[PATH_MAX];
	char privkey_file[PATH_MAX];
	char userkey_dir[PATH_MAX];
} config = { DEFAULT_PORT, DEFAULT_CERT_FILE, DEFAULT_KEY_FILE, "" };

/* Prints help message and exits. */
static inline void print_help(const char *cmdname)
{
	printf(USAGE_STRING "\n\n"
		"-h:\tprints this message and exits\n"
		"-v:\tprints version infos and exits\n"
		"-p:\tspecifies the listening port\n"
		"-c:\tspecifies the certificate file\n"
		"-k:\tspecifies the private key file\n"
		"-d:\tspecifies the directory where users' public keys are placed\n",
		cmdname);
}

/* Prints package name and version, then exits. */
static inline void print_version(void)
{
	puts(PACKAGE_STRING " (server)");
	puts(OPENSSL_VERSION_TEXT);
}

static bool init()
{
	X509 *cert = pem_read_x509_file(config.cert_file);
	if (!cert) {
		error_print();
		X509_free(cert);
		return false;
	}

	EVP_PKEY *privkey = pem_read_privkey(config.privkey_file, pass_cb);
	if (!privkey) {
		cout_printf_error("Can not open file '%s'.\n", config.privkey_file);
		error_print();
		return false;
	}


	int sock = net_listen(config.port, SOCK_STREAM);
	if (sock == -1){
			X_509_free(cert);
			EVP_PKEY_free(privkey);
			return false;
			close(sock);
	}

	int conn = net_accept(sock);
	if (conn == -1){
		close(sock);
		X_509_free(cert);
		EVP_PKEY_free(privkey);
		return false;
	}

	ctx = proto_ctx_new(sock, NULL, privkey, NULL);
	if (!ctx) {
		error_print();
		EVP_PKEY_free(privkey);
		X509_free(cert);
		close(sock);
		return false;
	}

	truct server_hello *hello = proto_recv_hello(ctx);
	if (!hello) {
		error_print(); //TODO
		proto_clear_last_error();
		proto_ctx_free(ctx);
		return false;
	}

	printf("username: %s\n", hello->username);
	int len = strlen(hello->username);
	char *filename = OPENSSL_malloc(len + 5);
	strcpy(filename, hello->username);
	strcpy(filename + len, ".pem");

	EVP_PKEY *peerkey = pem_read_pubkey(filename);
	OPENSSL_free(filename);
	if (!peerkey) {
		error_print(); //TODO
		X509_free(cert);
		proto_ctx_free(ctx);
		return false;
	}

	proto_ctx_set_peerkey(ctx, peerkey);

	if (!proto_verify_last_msg(ctx)){
		error_print();
		proto_ctx_free(ctx);
		return false;
	}

	if (!proto_send_cert(ctx, cert)){
		error_print();
		proto_ctx_free(ctx);
		return false;
	}

	X509_free(cert);

	if (!proto_send_hello(ctx, hello->username, hello->nonce)){
		error_print();
		proto_ctx_free(ctx);
		return false;
	}
	OPENSSL_free(hello);

	if (!proto_run_dh(ctx)) {
		error_print(); //TODO
		proto_ctx_free(ctx);
		return false;
	}
	proto_ctx_free(ctx);
	net_close(sock);
	return true;
}


static int test(void)
{
	error_enable_autoprint();
	X509* cert = pem_read_x509_file("server_cert.pem");
	if (!cert)
		return 1;
	EVP_PKEY *privkey = pem_read_privkey("server_privkey.pem", NULL, NULL);
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
	proto_ctx_free(ctx);
	net_close(sock);
}

int main(int argc, char **argv)
{
	memdbg_enable_debug();
	int opt;
	while ((opt = getopt(argc, argv, "+hvp:c:k:d:")) != -1)
		switch (opt) {
		case 'h':
			print_help(argv[0]);
			return 0;
		case 'v':
			print_version();
			return 0;
		case 'p':
			if (!string_to_uint16(optarg, &config.port))
				panicf("Invalid port number %s. Enter a value between 0 and 65535.",
					optarg);
			break;
		case 'c':
			strncpy(config.cert_file, optarg, PATH_MAX);
			config.cert_file[PATH_MAX - 1] = '\0';
			if (access(config.cert_file, R_OK) != 0) {
				cout_printf_error("Can not access file '%s'.\n", config.cert_file);
				panic(strerror(errno));
			}
			break;
		case 'k':
			strncpy(config.privkey_file, optarg, PATH_MAX);
			config.privkey_file[PATH_MAX - 1] = '\0';
			if (access(config.privkey_file, R_OK) != 0) {
				cout_printf_error("Can not access file '%s'.\n", config.privkey_file);
				panic(strerror(errno));
			}
			break;
		case 'd':
			strncpy(config.userkey_dir, optarg, PATH_MAX);
			config.userkey_dir[PATH_MAX - 1] = '\0';
			if (access(config.userkey_dir, R_OK) != 0) {
				cout_printf_error("Can not access file '%s'.\n", config.userkey_dir);
				panic(strerror(errno));
			}
			break;
		default:
			panicf("Invalid option: %s.\n" USAGE_STRING,
				argv[optind], argv[0]);
		}
	if (optind < argc)
		panicf("Invalid argument: %s.\n" USAGE_STRING,
			argv[optind], argv[0]);

	if (!init(config))
		return 1;



	return 0;
}
