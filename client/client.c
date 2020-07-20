#ifdef HAVE_CONFIG_H
#include <config.h>
#else
#define PACKAGE_STRING	"connect-4 1.0.0"
#endif /* HAVE_CONFIG_H */

#include "client/cin.h"
#include "client/connect4.h"
#include "client/game.h"
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

struct config {
	int force_ipv;
	uint16_t server_port;
	uint16_t game_port;
	char server_addr[254];
	char privkey_file[PATH_MAX];
	char ca_file[PATH_MAX];
	char crl_file[PATH_MAX];
};

static int force_ipv;
static int server_sock;
static PROTO_CTX *server_ctx;
static char username[MAX_USERNAME_LEN + 1];
static uint16_t game_port;
static EVP_PKEY *privkey;

#define _STRINGIZE(x) #x
#define STRINGIZE(x) _STRINGIZE(x)

/* Prints help message and exits. */
static inline void print_help(const char *cmdname)
{
	printf(USAGE_STRING "\n\n"
		"-h:\tprints this message and exits\n"
		"-v:\tprints version infos and exits\n"
		"-i:\tforce a specific IP protocol version (4 or 6)\n"
		"-H:\tspecifies the server hostname/address (default: " DEFAULT_SERVER_ADDR ")\n"
		"-p:\tspecifies the server port (default: " STRINGIZE(DEFAULT_SERVER_PORT) ")\n"
		"-l:\tspecifies the p2p listening port (default: " STRINGIZE(DEFAULT_GAME_PORT) ")\n"
		"-k:\tspecifies the private key file (default: <username>.pem)\n"
		"-a:\tspecifies the CA certificate file (default: " DEFAULT_CA_FILE ")\n"
		"-c:\tspecifies the CRL file (default: " DEFAULT_CRL_FILE ")\n",
		cmdname);
}

/* Prints package name and version, then exits. */
static inline void print_version(void)
{
	puts(PACKAGE_STRING " (client)");
	puts(OPENSSL_VERSION_TEXT);
}

static void print_cmd_help(void)
{
	puts("help\t\t- print this message.");
	puts("list\t\t- get the list of connected users.");
	puts("challenge <username>\t- challenge a user.");
	puts("quit/exit\t- close the application.");
}

static void list_users(void)
{
	struct user_list *ulist = proto_ask_player_list(server_ctx);
	if (!ulist) {
		error_print();
		return;
	}
	if (ulist->count == 0) {
		puts("No one online.");
		return;
	}
	printf("%-" STRINGIZE(MAX_USERNAME_LEN) "s\t%7s\n\n", "USERNAME", "STATUS");
	for (unsigned int i = 0; i < ulist->count; i++) {
		printf("%-" STRINGIZE(MAX_USERNAME_LEN) "s\t%7s\n",
			ulist->users[i].username,
			ulist->users[i].in_game ? "IN GAME" : "IDLE");
	}
}

static void start_game(const char *opponent, struct client_info *infos, bool challenger)
{
	struct game_info gameinfos;
	strcpy(gameinfos.yourname, username);
	strcpy(gameinfos.opponentname, opponent);
	gameinfos.game_port = game_port;
	gameinfos.opponent_port = infos->game_port;
	gameinfos.privkey = privkey;
	gameinfos.peerkey = pem_deserialize_pubkey(infos->key, infos->keylen);
	if (!gameinfos.peerkey) {
		error_print();
		return;
	}
	gameinfos.dhnonce = infos->dhnonce;
	strcpy(gameinfos.opponent_addr, infos->address);
	gameinfos.ipv = force_ipv;
	gameinfos.challenger = challenger;
	game_start(gameinfos);
	if (!proto_send_game_end(server_ctx))
		error_print();
}

static void challenge_user(const char *opponent)
{
	size_t len = strlen(opponent);
	if (len == 0 || len > MAX_USERNAME_LEN) {
		cout_print_error("Invalid username.");
		return;
	}
	struct client_info *infos;
	if (!proto_chall(server_ctx, opponent, &infos)) {
		error_print();
		return;
	}
	if (!infos) {
		printf("%s rejected your challenge.\n", opponent);
		return;
	}
	start_game(opponent, infos, true);
}

static bool is_valid_command(char *cmd, bool has_params)
{
	cmd = string_to_lower(cmd);
	return 	(string_starts_with("help", cmd) && !has_params)
		|| (string_starts_with("list", cmd) && !has_params)
		|| (string_starts_with("challenge", cmd) && has_params)
		|| (string_starts_with("quit", cmd) && !has_params)
		|| (string_starts_with("exit", cmd) && !has_params);
}

static void process_server_msg(void)
{
	struct chall_req *req = proto_recv_chall_req(server_ctx);
	if (!req) {
		if (error_get() == ECONNCLOSE) {
			error_print();
			EVP_PKEY_free(privkey);
			proto_ctx_free(server_ctx);
			exit(EXIT_FAILURE);
		}
		error_print();
		return;
	}
	char opponent[MAX_USERNAME_LEN + 1];
	strncpy(opponent, req->username, MAX_USERNAME_LEN);
	opponent[MAX_USERNAME_LEN] = '\0';
	bool res = cin_ask_question(true, "%s wants to play with you. Accept?", opponent);
	if (!proto_send_chall_res(server_ctx, res)) {
		error_print();
		return;
	}
	if (!res) {
		puts("Challenge rejected.");
		return;
	}
	struct client_info *infos = proto_recv_client_info(server_ctx);
	if (!infos) {
		error_print();
		return;
	}
	start_game(opponent, infos, false);
}

static void process_command(void)
{
	char params[MAX_CMD_SIZE];
	char cmd = cin_read_command(params, is_valid_command);
	switch (cmd) {
	case 'l':
		list_users();
		break;
	case 'c':
		challenge_user(params);
		break;
	case 'h':
		print_cmd_help();
		break;
	case 'q':
	case 'e':
		EVP_PKEY_free(privkey);
		proto_ctx_free(server_ctx);
		exit(EXIT_SUCCESS);
	case '?':
	default:
		cout_print_error("Invalid command.");
	}
}

static void repl(void)
{
	printf("\n");
	while (true) {
		printf("> ");
		fflush(stdout);
		fd_set readset;
		FD_ZERO(&readset);
		FD_SET(server_sock, &readset);
		FD_SET(STDIN_FILENO, &readset);
		int nfds = (server_sock > STDIN_FILENO ? server_sock : STDIN_FILENO) + 1;
		int ready = select(nfds, &readset, NULL, NULL, NULL);
		if (ready == -1 && errno == EINTR) {
			cout_print_error("Interrupted!");
			return;
		}
		if (ready == -1) {
			REPORT_ERR(ENET, "select() returned -1.");
			error_print();
			return;
		}
		for (int fd = 0; fd < nfds; fd++) {
			if (!FD_ISSET(fd, &readset))
				continue;
			if (fd == server_sock) {
				printf("\n");
				process_server_msg();
				continue;
			}
			if (fd == STDIN_FILENO)
				process_command();
		}
	}
}

static X509 *get_server_cert(void)
{
	X509 *cert = proto_recv_cert(server_ctx);
	if (!cert)
		return NULL;

	if (!x509_verify(cert)) {
		X509_free(cert);
		return NULL;
	}
	return cert;

}

static EVP_PKEY *get_server_pubkey(void)
{
	X509 *cert = get_server_cert();
	if (!cert)
		return NULL;
	EVP_PKEY *pubkey = x509_extract_pubkey(cert);
	X509_free(cert);
	return pubkey;
}


static bool do_hello(void)
{
	if (!proto_send_hello(server_ctx, username, game_port))
		return false;
	EVP_PKEY *serverkey = get_server_pubkey();
	if (!serverkey)
		return false;
	proto_ctx_set_peerkey(server_ctx, serverkey);
	struct server_hello *hello = proto_recv_hello(server_ctx);
	if (!hello)
		return false;
	return true;
}

static int pass_cb(char *buf, int size, __attribute__((unused)) int rwflag, void *u)
{
	char *pass = cin_ask_passphrase((const char *)u, size);
	if (!pass)
		return -1;
	size_t len = strlen(pass);
	memcpy(buf, pass, len + 1);
	OPENSSL_clear_free(pass, len + 1);
	return len;
}

static bool ask_username(void)
{
	int usernamelen;
	while (true) {
		printf("Enter your username: ");
		fflush(stdout);
		usernamelen = cin_read_line(username, MAX_USERNAME_LEN + 1);
		if (usernamelen > MAX_USERNAME_LEN) {
			puts("Username musr contains " STRINGIZE(MAX_USERNAME_LEN) " characters at most.");
			continue;
		}
		if (usernamelen < 0) {
			puts("Reached EOF.");
			return false;
		}
		break;
	}
	return true;
}

static EVP_PKEY *load_user_privkey(char *privkey_file)
{
	if (!ask_username())
		return NULL;
	if (!privkey_file || *privkey_file == '\0') {
		strcpy(privkey_file, username);
		strcpy(privkey_file + strlen(username), ".pem");
	}
	EVP_PKEY *privkey = pem_read_privkey(privkey_file, pass_cb, username);
	if (!privkey) {
		cout_printf_error("Can not open file '%s'.\n", privkey_file);
		return NULL;
	}
	return privkey;

}

static void init_session(struct config cfg)
{
	game_port = cfg.game_port;
	do {
		if (!x509_store_init(cfg.ca_file, cfg.crl_file))
			break;
		privkey = load_user_privkey(cfg.privkey_file);
		if (!privkey)
			break;
		server_ctx = proto_connect_to_server(cfg.server_addr,
			cfg.server_port, privkey, cfg.force_ipv, &server_sock);
		if (!server_ctx || !do_hello() || !proto_run_dh(server_ctx, true, 0))
			break;
		x509_store_free();
		return;
	} while(0);

	error_print();
	EVP_PKEY_free(privkey);
	x509_store_free();
	proto_ctx_free(server_ctx);
	exit(EXIT_FAILURE);
}

/* Client entry-point. */
int main(int argc, char **argv)
{
	memdbg_enable_debug();
	int opt;
	struct config cfg = { 0, DEFAULT_SERVER_PORT, DEFAULT_GAME_PORT,
		DEFAULT_SERVER_ADDR, "", DEFAULT_CA_FILE, DEFAULT_CRL_FILE };

	while ((opt = getopt(argc, argv, "+:hvi:H:p:l:k:a:c:")) != -1)
		switch (opt) {
		case 'h':
			print_help(argv[0]);
			return 0;
		case 'v':
			print_version();
			return 0;
		case 'i':
			if (!string_to_int(optarg, &cfg.force_ipv)
					|| (cfg.force_ipv != 4 && cfg.force_ipv != 6))
				panicf("Invalid option argument for -i: %s.",
					optarg);
			break;
		case 'H':
			strncpy(cfg.server_addr, optarg, 254);
			cfg.server_addr[253] = '\0';
			break;
		case 'p':
			if (!string_to_uint16(optarg, &cfg.server_port))
				panicf("Invalid port number %s. Enter a value between 0 and 65535.",
					optarg);
			break;
		case 'l':
			if (!string_to_uint16(optarg, &cfg.game_port))
				panicf("Invalid port number %s. Enter a value between 0 and 65535.",
					optarg);
			break;
		case 'k':
			strncpy(cfg.privkey_file, optarg, PATH_MAX);
			cfg.privkey_file[PATH_MAX - 1] = '\0';
			if (access(cfg.privkey_file, R_OK) != 0) {
				cout_printf_error("Can not access file '%s'.\n", cfg.privkey_file);
				panicf(strerror(errno));
			}
			break;
		case 'a':
			strncpy(cfg.ca_file, optarg, PATH_MAX);
			cfg.ca_file[PATH_MAX - 1] = '\0';
			if (access(cfg.ca_file, R_OK) != 0) {
				cout_printf_error("Can not access file '%s'.\n", cfg.ca_file);
				panic(strerror(errno));
			}
			break;
		case 'c':
			strncpy(cfg.crl_file, optarg, PATH_MAX);
			cfg.crl_file[PATH_MAX - 1] = '\0';
			if (access(cfg.crl_file, R_OK) != 0) {
				cout_printf_error("Can not access file '%s'.\n", cfg.crl_file);
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

	force_ipv = cfg.force_ipv;
	init_session(cfg);
	repl();
	EVP_PKEY_free(privkey);
	proto_ctx_free(server_ctx);
	return 0;
}
