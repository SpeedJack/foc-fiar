#include "client/cin.h"
#include "client/connect4.h"
#include "client/game.h"
#include "cout.h"
#include "error.h"
#include "net.h"
#include "pem.h"
#include <errno.h>
#include <signal.h>
#include <string.h>

static const int signals[] = {SIGHUP, SIGINT, SIGTERM, 0};

static int game_sock;
static PROTO_CTX *game_proto_ctx;

static void sighandler(__attribute__((unused)) int signum)
{
	puts("\nExiting game...");
	if (game_proto_ctx && !proto_send_error(game_proto_ctx, ECONNCLOSE, "Surrender."))
		error_print();
	puts("*** Game ended! ***\n");
	proto_ctx_free(game_proto_ctx);
	game_proto_ctx = NULL;
}

static void sighandler_init(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = sighandler;
	for (int i = 0; signals[i] > 0; i++)
		if (sigaction(signals[i], &sa, NULL) == -1)
			panic(strerror(errno));
}

static bool opponent_move(enum c4_result *res)
{
	puts("Waiting for opponent to move...");
	struct game_move *move = proto_recv_game_move(game_proto_ctx);
	if (!move) {
		if (game_proto_ctx)
			error_print();
		return false;
	}
	int col = move->column;
	*res = c4_insert(col);
	switch(*res) {
	case INVALID_COLUMN:
	case FULL_COLUMN:
		cout_print_error("Opponent inserted a disc on an invalid column.");
		if (!proto_send_error(game_proto_ctx, EINVMOVE, "Invalid move."))
			error_print();
		return false;
	case FULL_BOARD:
		if (!proto_send_error(game_proto_ctx, EINVMOVE, "Board is full."))
			error_print();
		return true;
	default:
		printf("Opponent move: %d\n", col);
		return true;
	}
}

static bool user_move(enum c4_result *res)
{
	puts("Make your move!");
	while (true) {
		printf("Column number: ");
		fflush(stdout);
		int col = cin_read_uint();
		if (col < 0)
			return false;
		*res = c4_insert(col);
		switch (*res) {
		case INVALID_COLUMN:
			puts("Invalid column.");
			continue;
		case FULL_COLUMN:
			puts("The choosen column is full. Choose another column.");
			continue;
		case FULL_BOARD:
			return true;
		default:
			if (!proto_send_game_move(game_proto_ctx, col)) {
				error_print();
				return false;
			}
			return true;
		}
	}
}

static void game_loop(void)
{
	c4_print_board();
	while (true) {
		enum c4_result result;
		bool ok;
		if (c4_is_my_turn())
			ok = user_move(&result);
		else
			ok = opponent_move(&result);
		if (!ok)
			return;
		c4_print_board();
		switch (result) {
		case OK:
		case INVALID_COLUMN:
		case FULL_COLUMN:
			break;
		case OK_FULL_BOARD:
		case FULL_BOARD:
			puts("Board is full.");
			return;
		case OPPONENT_WIN:
			puts("You lost! Better luck next time...");
			return;
		case PLAYER_WIN:
			puts("You won! Congratulations!");
			return;
		}
	}
}

void game_start(struct game_info infos)
{
	net_set_nonblocking(true);
	game_sock = net_udp_bind(infos.game_port);
	if (game_sock == -1) {
		error_print();
		return;
	}
	char service[6];
	snprintf(service, 6, "%d", infos.opponent_port);
	struct addrinfo *peeraddr = net_getaddrinfo(infos.opponent_addr, service,
		infos.ipv == 6 ? AF_INET6 : infos.ipv == 4 ? AF_INET : AF_UNSPEC, SOCK_DGRAM);
	if (!peeraddr) {
		error_print();
		return;
	}
	game_proto_ctx = proto_ctx_new(game_sock, peeraddr, infos.privkey, infos.peerkey);
	if (!game_proto_ctx) {
		error_print();
		return;
	}
	sighandler_init();
	if (!proto_run_dh(game_proto_ctx, infos.challenger, infos.dhnonce)) {
		proto_ctx_free(game_proto_ctx);
		error_print();
		return;
	}
	printf("*** Game started with %s! ***\n", infos.opponentname);
	puts("You can exit the game at any time with CTRL-C.\n");
	c4_init(infos.challenger);
	game_loop();
	if (!game_proto_ctx)
		return;
	puts("*** Game ended! ***\n");
	proto_ctx_free(game_proto_ctx);
}
