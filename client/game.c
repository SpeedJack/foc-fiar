#include <arpa/inet.h>
#include "client/game.h"
#include "net.h"
#include "pem.h"

static int game_sock;
static PROTO_CTX *game_proto_ctx;

void game_start(struct game_info infos)
{
	/*printf("Game Started!\nYour name: %s\nYour port: %d\nOpponent: %s\nAddress: %s\nOpponent port: %d\nDH nonce: %d\nKey len: %d\n",
		yourname, port, opponentname, infos.address, infos.game_port, infos.dhnonce, infos.keylen);*/

	printf("infos.addr: %s\n", infos.opponent_addr);
	game_sock = net_udp_bind(infos.game_port);
	if (game_sock == -1) {
		error_print();
		return;
	}
	char service[6];
	snprintf(service, 6, "%d", infos.opponent_port);
	struct addrinfo *peeraddr = net_getaddrinfo(infos.opponent_addr, service, AF_INET6, SOCK_DGRAM);
	if (!peeraddr) {
		error_print();
		return;
	}
	char straddr[ADDRSTRLEN];
	inet_ntop(
		AF_INET6,
		&(((struct sockaddr_in6 *)peeraddr->ai_addr)->sin6_addr),
		straddr, ADDRSTRLEN);
	printf("Address: %s\n", straddr);
	game_proto_ctx = proto_ctx_new(game_sock, peeraddr, infos.privkey, infos.peerkey);
	if (!game_proto_ctx) {
		error_print();
		return;
	}
	if (!proto_run_dh(game_proto_ctx, true, infos.dhnonce)) {
		error_print();
		return;
	}
	puts("Connected");
}
