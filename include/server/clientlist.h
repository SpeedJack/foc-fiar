#ifndef SERVER_CLIENTLIST_H
#define SERVER_CLIENTLIST_H

#include "protocol.h"

struct client {
	PROTO_CTX *ctx;
	int socket;
	char username[MAX_USERNAME_LEN + 1];
	char address[ADDRSTRLEN];
	uint16_t game_port;
	bool in_game;
	struct client *opponent;
	EVP_PKEY *pubkey;
};

extern void clientlist_init(void);
extern struct client *clientlist_insert(struct client client);
extern struct user_list *clientlist_get_user_list(struct client *exclude);
extern struct client *clientlist_add(PROTO_CTX *ctx, int socket, struct sockaddr *addr);
extern bool clientlist_register(struct client *client);
extern struct client *clientlist_get(int socket);
extern struct client *clientlist_search(const char username[MAX_USERNAME_LEN + 1]);
extern int clientlist_getfdset(fd_set *set);
extern void clientlist_remove(struct client *client);
extern void clientlist_free(void);

#endif /* SERVER_CLIENTLIST_H */
