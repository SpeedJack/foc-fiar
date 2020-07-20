#ifndef CLIENT_GAME_H
#define CLIENT_GAME_H

#include "client/proto.h"

struct game_info {
	char yourname[MAX_USERNAME_LEN + 1];
	char opponentname[MAX_USERNAME_LEN + 1];
	uint16_t game_port;
	uint16_t opponent_port;
	EVP_PKEY *privkey;
	EVP_PKEY *peerkey;
	uint32_t dhnonce;
	char opponent_addr[ADDRSTRLEN];
	int ipv;
	bool challenger;
};

extern void game_start(struct game_info infos);

#endif /* CLIENT_GAME_H */
