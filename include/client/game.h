#ifndef CLIENT_GAME_H
#define CLIENT_GAME_H

#include "client/proto.h"

extern void game_start(const char *yourname, const char *opponentname, uint16_t port,
	EVP_PKEY *privkey, struct client_info infos);

#endif /* CLIENT_GAME_H */
