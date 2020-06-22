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
#include "memdbg.h"
#include "pem.h"
#include "random.h"
#include "stringop.h"
#include <openssl/opensslv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define USAGE_STRING	\
	"Usage: %s [-h] [-v] [-i <num>] [-H <host>] [-p <port>] [-l <port>] [-k <key-file>] [-a <cert-file>] [-c <cert-file>]"

#define DEFAULT_SERVER_ADDR	"localhost"
#define DEFAULT_SERVER_PORT	8888
#define DEFAULT_GAME_PORT	5656
#define DEFAULT_CA_FILE		"ca.pem"
#define DEFAULT_CRL_FILE	"crl.pem"

static struct {
	int force_ipv;
	uint16_t server_port;
	uint16_t game_port;
	char server_addr[254];
	char privkey_file[PATH_MAX];
	char ca_file[PATH_MAX];
	char crl_file[PATH_MAX];
} config = { 0, DEFAULT_SERVER_PORT, DEFAULT_GAME_PORT,
		DEFAULT_SERVER_ADDR, "", DEFAULT_CA_FILE, DEFAULT_CRL_FILE };

static PROTO_CTX *ctx;

static bool handle_error(void)
{
	enum error_code code = error_get();
	if (code == ENOERR)
		return true;
	enum err_code peererr = proto_get_last_error();
	char *msg = error_get_message();
	error_print();
	switch (code) {
	case EINVMSG:
	case ETOOBIG:
	case EREPLAY:
	case EINVACK:
	case EINVSIG:
	case EGCM:
	case ETOOMUCH:
	case EINVCERT:
		proto_send_error(ctx, INVMSG, msg);
		return false;
	case EPEERERR:
		switch (peererr) {
		case NOERR:
		case INVMSG:
		case INVMOVE:
			return true;
		case NOAUTH:
		case INVSIG:
		case GCMERR:
		default:
			return false;
		}
	case EALLOC:
	case EFILE:
	case ENET:
	case EOSSL:
	case EUNSPEC:
	default:
		return false;
	}
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
		"-l:\tspecifies the p2p listening port\n"
		"-k:\tspecifies the private key file\n"
		"-a:\tspecifies the CA certificate file\n"
		"-c:\tspecifies the CRL file\n",
		cmdname);
}

/* Prints package name and version, then exits. */
static inline void print_version(void)
{
	puts(PACKAGE_STRING " (client)");
	puts(OPENSSL_VERSION_TEXT);
}

static int pass_cb(char *buf, int size, __attribute__((unused)) int rwflag, void *u)
{
	char password[size];
	int len;
	while (true) {
		printf("Enter pass phrase for \"%s\": ", (char *)u);
		fflush(stdout);
		len = cin_read_line(password, size);
		if (len < 0 || len > size - 1) {
			cout_print_error("Passsword is too long.");
			continue;
		}
		break;
	}
	memcpy(buf, password, len);
	return len;
}

static void start_repl()
{
}

static bool init()
{
	char username[MAX_USERNAME_LEN + 1];
	int usernamelen;
	while (true) {
		printf("Enter your username: ");
		fflush(stdout);
		usernamelen = cin_read_line(username, MAX_USERNAME_LEN + 1);
		if (usernamelen > MAX_USERNAME_LEN) {
			printf("Username must contains %d characters at most.\n", MAX_USERNAME_LEN);
			continue;
		}
		if (usernamelen < 0) {
			printf("Reached End-Of-File.\n");
			return false;
		}
		break;
	}

	if (!config.privkey_file || *config.privkey_file == '\0') {
		strncpy(config.privkey_file, username, usernamelen + 1);
		strcpy(config.privkey_file + usernamelen, ".pem");
	}

	EVP_PKEY *privkey = pem_read_privkey(config.privkey_file, pass_cb, username);
	if (!privkey) {
		cout_printf_error("Can not open file '%s'.\n", config.privkey_file);
		error_print();
		return false;
	}

	X509 *ca = pem_read_x509_file(config.ca_file);
	if (!ca) {
		error_print();
		EVP_PKEY_free(privkey);
		return false;
	}
	X509_CRL *crl = x509_read_crl(config.crl_file);
	if (!crl) {
		error_print();
		EVP_PKEY_free(privkey);
		X509_free(ca);
		return false;
	}

	char service[6];
	snprintf(service, 6, "%d", config.server_port);
	int ipv = AF_UNSPEC;
	if (config.force_ipv != 0)
		ipv = config.force_ipv == 4 ? AF_INET : AF_INET6;
	struct addrinfo *serveraddr = net_getaddrinfo(config.server_addr, service, ipv, SOCK_STREAM);
	if (!serveraddr) {
		error_print();
		EVP_PKEY_free(privkey);
		X509_free(ca);
		X509_CRL_free(crl);
		return false;
	}

	int sock = net_connect(*serveraddr);
	if (sock == -1) {
		error_print();
		freeaddrinfo(serveraddr);
		EVP_PKEY_free(privkey);
		X509_free(ca);
		X509_CRL_free(crl);
		return false;
	}

	ctx = proto_ctx_new(sock, serveraddr, privkey, NULL);
	if (!ctx) {
		error_print();
		freeaddrinfo(serveraddr);
		EVP_PKEY_free(privkey);
		X509_free(ca);
		X509_CRL_free(crl);
		close(sock);
		return false;
	}

	uint32_t nonce = random_nonce();
	if (!proto_send_hello(ctx, username, config.game_port, nonce)) {
		error_print(); //TODO
		X509_free(ca);
		X509_CRL_free(crl);
		proto_ctx_free(ctx);
		return false;
	}

	X509 *cert = proto_recv_cert(ctx);
	if (!cert) {
		error_print(); //TODO
		X509_free(ca);
		X509_CRL_free(crl);
		proto_ctx_free(ctx);
		return false;
	}
	if (!x509_verify(cert, ca, crl)) {
		error_print(); //TODO
		X509_free(ca);
		X509_CRL_free(crl);
		proto_ctx_free(ctx);
		return false;
	}
	X509_free(ca);
	X509_CRL_free(crl);
	EVP_PKEY *peerkey = x509_extract_pubkey(cert);
	if (!peerkey) {
		error_print(); //TODO
		X509_free(cert);
		proto_ctx_free(ctx);
		return false;
	}
	X509_free(cert);
	proto_ctx_set_peerkey(ctx, peerkey);

	struct server_hello *hello = proto_recv_hello(ctx);
	if (!hello) {
		error_print(); //TODO
		proto_ctx_free(ctx);
		return false;
	}
	if (hello->nonce != nonce) {
		cout_print_error("Invalid nonce in SERVER_HELLO.");
		OPENSSL_free(hello);
		proto_ctx_free(ctx);
		return false;
	}
	OPENSSL_free(hello);

	if (!proto_run_dh(ctx)) {
		error_print(); //TODO
		proto_ctx_free(ctx);
		return false;
	}

	printf("Successfully connected to the server!\n");
	proto_ctx_free(ctx); //TODO
	return true;
}
static void recv_game_move (struct game_move gm){
	c4_insert(gm.column);
	/*print board*/
	c4_print_board();
	/*insert move*/
	struct game_move my_gm;
	printf("Choose column: ");
	my_gm.column=getchar();
	send_game_move(my_gm);
}

static void send_game_move(struct game_move gm){
	proto_send_gcm(ctx, gm, sizeof(gm));
}

/* Client entry-point. */
int main(int argc, char **argv)
{
	memdbg_enable_debug();
	int opt;

	while ((opt = getopt(argc, argv, "+:hvi:H:p:l:k:a:c:")) != -1)
		switch (opt) {
		case 'h':
			print_help(argv[0]);
			return 0;
		case 'v':
			print_version();
			return 0;
		case 'i':
			if (!string_to_int(optarg, &config.force_ipv)
					|| (config.force_ipv != 4 && config.force_ipv != 6))
				panicf("Invalid option argument for -i: %s.",
					optarg);
			break;
		case 'H':
			strncpy(config.server_addr, optarg, 254);
			config.server_addr[253] = '\0';
			break;
		case 'p':
			if (!string_to_uint16(optarg, &config.server_port))
				panicf("Invalid port number %s. Enter a value between 0 and 65535.",
					optarg);
			break;
		case 'l':
			if (!string_to_uint16(optarg, &config.game_port))
				panicf("Invalid port number %s. Enter a value between 0 and 65535.",
					optarg);
			break;
		case 'k':
			strncpy(config.privkey_file, optarg, PATH_MAX);
			config.privkey_file[PATH_MAX - 1] = '\0';
			if (access(config.privkey_file, R_OK) != 0) {
				cout_printf_error("Can not access file '%s'.\n", config.privkey_file);
				panicf(strerror(errno));
			}
			break;
		case 'a':
			strncpy(config.ca_file, optarg, PATH_MAX);
			config.ca_file[PATH_MAX - 1] = '\0';
			if (access(config.ca_file, R_OK) != 0) {
				cout_printf_error("Can not access file '%s'.\n", config.ca_file);
				panic(strerror(errno));
			}
			break;
		case 'c':
			strncpy(config.crl_file, optarg, PATH_MAX);
			config.crl_file[PATH_MAX - 1] = '\0';
			if (access(config.crl_file, R_OK) != 0) {
				cout_printf_error("Can not access file '%s'.\n", config.crl_file);
				panic(strerror(errno));
			}
			break;
		default:
			panicf("Invalid option: %c.\n" USAGE_STRING,
				optopt, argv[0]);
		}

	if (optind < argc)
		panicf("Invalid argument: %s.\n" USAGE_STRING,
			argv[optind], argv[0]);

	if (!init(config))
		return 1;
	start_repl();

	return 0;
}
