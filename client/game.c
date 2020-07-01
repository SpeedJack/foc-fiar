#include "client/game.h"

void game_start(const char *yourname, const char *opponentname, uint16_t port,
	EVP_PKEY *privkey, struct client_info infos)
{
	printf("Game Started!\nYour name: %s\nYour port: %d\nOpponent: %s\nAddress: %s\nOpponent port: %d\nDH nonce: %d\nKey len: %d\n",
		yourname, port, opponentname, infos.address, infos.game_port, infos.dhnonce, infos.keylen);
}
