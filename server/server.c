#ifdef HAVE_CONFIG_H
#include <config.h>
#else
#define PACKAGE_STRING	"connect-4 1.0.0"
#endif /* HAVE_CONFIG_H */

#include "server/clientlist.h"
#include "server/proto.h"
#include "cout.h"
#include "dirent.h"
#include "error.h"
#include "memdbg.h"
#include "net.h"
#include "pem.h"
#include "random.h"
#include "stringop.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define USAGE_STRING	\
	"Usage: %s [-h] [-v] [-p <port>] [-c <cert-file>] [-k <key-file>] [-d <userkeys-dir>]"

#ifdef _WIN32
#define DIR_SEPARATOR		"\\"
#else
#define DIR_SEPARATOR		"/"
#endif /* _WIN32 */
#define DIR_SEPARATOR_CHAR	*DIR_SEPARATOR

#define USERNAME_ALLOWED_CHARS	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

#define DEFAULT_PORT		8888
#define DEFAULT_CERT_FILE	"server_cert.pem"
#define DEFAULT_KEY_FILE	"server_privkey.pem"
#define DEFAULT_USERKEY_DIR	"users" DIR_SEPARATOR

#define SOCKET_TIMEOUT		10000

struct config {
	uint16_t port;
	char cert_file[PATH_MAX];
	char privkey_file[PATH_MAX];
};

static int listen_sock;
static X509 *server_cert;
static EVP_PKEY *privkey;
static char userkey_dir[PATH_MAX];

#define _STRINGIZE(x) #x
#define STRINGIZE(x) _STRINGIZE(x)

/* Prints help message and exits. */
static inline void print_help(const char *cmdname)
{
	printf(USAGE_STRING "\n\n"
		"-h:\tprints this message and exits\n"
		"-v:\tprints version infos and exits\n"
		"-p:\tspecifies the listening port (default: " STRINGIZE(DEFAULT_PORT) ")\n"
		"-c:\tspecifies the certificate file (default: " DEFAULT_CERT_FILE ")\n"
		"-k:\tspecifies the private key file (default: " DEFAULT_KEY_FILE ")\n"
		"-d:\tspecifies the directory where users' public keys are placed\n"
		"\t(default: " DEFAULT_USERKEY_DIR ")\n",
		cmdname);
}

/* Prints package name and version, then exits. */
static inline void print_version(void)
{
	puts(PACKAGE_STRING " (server)");
	puts(OPENSSL_VERSION_TEXT);
}

static void process_challenge_res(struct client *client, struct chall_res *cres)
{
	if (!client->opponent) {
		if (!proto_send_error(client->ctx, EINVMSG_P, "You are not currently challenged."))
			error_print();
		goto clean_return;
	}
	if (client->in_game) {
		if (!proto_send_error(client->ctx, EINVMSG_P, "You are already in game."))
			error_print();
		goto clean_return;
	}
	if (!proto_send_chall_res(client->opponent->ctx, cres->accept)) {
		if (!proto_send_current_error(client->opponent->ctx)
			|| !proto_send_current_error(client->ctx))
			error_print();
		goto clean_return;
	}
	if (!cres->accept)
		goto clean_return;
	uint32_t nonce = random_nonce();
	if (nonce == 0) {
		if (!proto_send_current_error(client->ctx)
			|| !proto_send_current_error(client->opponent->ctx))
			error_print();
		goto clean_return;
	}
	if (!proto_send_client_info(client->opponent->ctx, client->address,
		client->game_port, client->pubkey, nonce)) {
		if (!proto_send_current_error(client->ctx))
			error_print();
		goto clean_return;
	}
	if (!proto_send_client_info(client->ctx, client->address,
		client->game_port, client->pubkey, nonce)) {
		error_print();
		goto clean_return;
	}
	client->opponent->in_game = true;
	client->in_game = true;
	return;
clean_return:
	client->opponent->opponent = NULL;
	client->opponent->in_game = false;
	client->opponent = NULL;
	client->in_game = false;
}

static void process_challenge_req(struct client *client, struct chall_req *creq)
{
	if (client->opponent || client->in_game) {
		if (!proto_send_error(client->ctx, EINVMSG_P, "You are already in a game."))
			error_print();
		return;
	}
	struct client *opponent = clientlist_search(creq->username);
	if (!opponent || opponent == client) {
		if (!proto_send_error(client->ctx, ENOUSER, "Can not find the specified user."))
			error_print();
		return;
	}
	if (opponent->opponent || opponent->in_game) {
		if (!proto_send_error(client->ctx, ENOUSER, "Opponent is already in game."))
			error_print();
		return;
	}
	if (!proto_send_chall_req(opponent->ctx, client->username)) {
		if (!proto_send_current_error(client->ctx))
			error_print();
		return;
	}
	client->opponent = opponent;
	client->in_game = false;
	opponent->opponent = client;
	opponent->in_game = false;
}

static void process_player_list_req(struct client *client)
{
	struct user_list *ul = clientlist_get_user_list(client);
	if (!ul) {
		if (!proto_send_current_error(client->ctx))
			error_print();
		return;
	}
	if (!proto_send_player_list(client->ctx, ul))
		clientlist_remove(client);
	OPENSSL_free(ul);
}

static bool valid_username(const char *username)
{
	size_t len = strlen(username);
	if (len == 0 || len > MAX_USERNAME_LEN)
		return false;
	for (const char *c = username; *c != '\0'; c++)
		if (!strchr(USERNAME_ALLOWED_CHARS, *c))
			return false;
	return true;
}

static void process_hello(struct client *client, struct client_hello *hello)
{
	if (!valid_username(hello->username)) {
		if (proto_send_error(client->ctx, EINVMSG, "Invalid username."))
			error_print();
		return;
	}
	client->game_port = hello->game_port;
	strncpy(client->username, hello->username, MAX_USERNAME_LEN);
	client->username[MAX_USERNAME_LEN] = '\0';
	char userkeyfile[PATH_MAX + MAX_USERNAME_LEN + 5];
	strncpy(userkeyfile, userkey_dir, PATH_MAX);
	strncat(userkeyfile, hello->username, MAX_USERNAME_LEN + 1);
	strcat(userkeyfile, ".pem");
	EVP_PKEY *peerkey = pem_read_pubkey(userkeyfile);
	if (!peerkey) {
		if (!proto_send_error(client->ctx, ENOREG, "Server can not find the public key of the specified user."))
			error_print();
		return;
	}
	proto_ctx_set_peerkey(client->ctx, peerkey);
	if (!proto_verify_last_msg(client->ctx)) {
		if (!proto_send_current_error(client->ctx))
			error_print();
		clientlist_remove(client);
		return;
	}
	if (!proto_send_cert(client->ctx, server_cert)
		|| !proto_send_hello(client->ctx, hello->username)
		|| !proto_run_dh(client->ctx, false)) {
		if (!proto_send_current_error(client->ctx))
			error_print();
		clientlist_remove(client);
	}
	client->pubkey = peerkey;
	if (!clientlist_register(client)) {
		if (!proto_send_current_error(client->ctx))
			error_print();
		clientlist_remove(client);
	}
}

static void process_request(struct client *client)
{
	enum msg_type type;
	size_t len;
	void *msg = proto_recv(client->ctx, &type, &len);
	if (!msg) {
		if (error_get() == ECONNCLOSE) {
			error_clear();
			clientlist_remove(client);
			return;
		}
		if (!proto_send_current_error(client->ctx))
			error_print();
		return;
	}
	if (type != CLIENT_HELLO && !client->pubkey) {
		proto_send_error(client->ctx, ENOREG, "Client not registered (handshake required).");
		return;
	}
	switch (type) {
	case CLIENT_HELLO:
		process_hello(client, (struct client_hello *)msg);
		break;
	case PLAYER_LIST_REQ:
		process_player_list_req(client);
		break;
	case CHALLENGE_REQ:
		process_challenge_req(client, (struct chall_req *)msg);
		break;
	case CHALLENGE_RES:
		process_challenge_res(client, (struct chall_res *)msg);
		break;
	default:
		proto_send_error(client->ctx, EINVMSG_P, "Invalid request.");
		break;
	}
}

static void accept_connection(void)
{
	struct sockaddr addr;
	socklen_t addrlen;
	int conn = net_accept(listen_sock, &addr, &addrlen);
	if (conn == -1) {
		error_print();
		return;
	}
	PROTO_CTX *ctx = proto_ctx_new(conn, NULL, privkey, NULL);
	if (!ctx) {
		error_print();
		net_close(conn);
		return;
	}
	if (!net_set_timeout(conn, SOCKET_TIMEOUT)
		|| !clientlist_add(ctx, conn, &addr)) {
		if (!proto_send_current_error(ctx))
			error_print();
		proto_ctx_free(ctx);
	}
}

static void server_loop(void)
{
	while (true) {
		fd_set readset;
		int nfds = clientlist_getfdset(&readset);
		FD_SET(listen_sock, &readset);
		nfds = (listen_sock > nfds ? listen_sock : nfds) + 1;
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
		for (int sock = 0; sock < nfds; sock++) {
			if (!FD_ISSET(sock, &readset))
				continue;
			if (sock == listen_sock) {
				accept_connection();
				continue;
			}
			struct client *client = clientlist_get(sock);
			if (!client) {
				cout_printf_error("Received a message on socket %d but no client registered on this socket.", sock);
				continue;
			}
			process_request(client);
		}
	}
}

static bool init(struct config cfg)
{
	server_cert = pem_read_x509_file(cfg.cert_file);
	if (!server_cert) {
		error_print();
		return false;
	}

	privkey = pem_read_privkey(cfg.privkey_file, NULL, NULL);
	if (!privkey) {
		cout_printf_error("Can not open file '%s'.\n", cfg.privkey_file);
		error_print();
		X509_free(server_cert);
		return false;
	}

	listen_sock = net_listen(cfg.port, SOCK_STREAM);
	if (listen_sock == -1) {
		error_print();
		X509_free(server_cert);
		EVP_PKEY_free(privkey);
		return false;
	}
	clientlist_init();
	return true;
}

int main(int argc, char **argv)
{
	memdbg_enable_debug();
	int opt;
	struct config cfg = { DEFAULT_PORT, DEFAULT_CERT_FILE, DEFAULT_KEY_FILE };
	strcpy(userkey_dir, DEFAULT_USERKEY_DIR);

	while ((opt = getopt(argc, argv, "+hvp:c:k:d:")) != -1)
		switch (opt) {
		case 'h':
			print_help(argv[0]);
			return 0;
		case 'v':
			print_version();
			return 0;
		case 'p':
			if (!string_to_uint16(optarg, &cfg.port))
				panicf("Invalid port number %s. Enter a value between 0 and 65535.",
					optarg);
			break;
		case 'c':
			strncpy(cfg.cert_file, optarg, PATH_MAX);
			cfg.cert_file[PATH_MAX - 1] = '\0';
			if (access(cfg.cert_file, R_OK) != 0) {
				cout_printf_error("Can not access file '%s'.\n", cfg.cert_file);
				panic(strerror(errno));
			}
			break;
		case 'k':
			strncpy(cfg.privkey_file, optarg, PATH_MAX);
			cfg.privkey_file[PATH_MAX - 1] = '\0';
			if (access(cfg.privkey_file, R_OK) != 0) {
				cout_printf_error("Can not access file '%s'.\n", cfg.privkey_file);
				panic(strerror(errno));
			}
			break;
		case 'd':
			strncpy(userkey_dir, optarg, PATH_MAX);
			userkey_dir[PATH_MAX - 1] = '\0';
			size_t dirlen = strlen(userkey_dir);
			for (unsigned int i = 0; i < dirlen; i++)
				if (userkey_dir[i] == '/'
					|| userkey_dir[i] == '\\')
					userkey_dir[i] = DIR_SEPARATOR_CHAR;
			if (!string_ends_with(userkey_dir, DIR_SEPARATOR)) {
				userkey_dir[dirlen] = DIR_SEPARATOR_CHAR;
				userkey_dir[dirlen + 1] = '\0';
			}
			DIR *dir = opendir(userkey_dir);
			if (dir) {
				closedir(dir);
			} else {
				cout_printf_error("Can not open directory '%s'.\n", userkey_dir);
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

	if (!init(cfg))
		return 1;
	server_loop();
	EVP_PKEY_free(privkey);
	clientlist_free();
	X509_free(server_cert);
	close(listen_sock);
	return 1;
}
