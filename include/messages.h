#ifndef COMMON_MESSAGES_H
#define COMMON_MESSAGES_H

#include <stdbool.h>
#include <stdint.h>

#define ADDRSTRLEN		46	/* = INET6_ADDRSTRLEN */
#define MAX_USERNAME_LEN	32

enum __attribute__((packed)) msg_type {
	CLIENT_HELLO, SERVER_HELLO, SERVER_CERT, DHKEY,
	PLAYER_LIST_REQ, PLAYER_LIST,
	CHALLENGE_REQ, CHALLENGE_RES, PLAYER_DETAILS,
	GAME_MOVE, GAME_MOVE_ACK, GAME_END,
	ERROR
};

struct __attribute__((packed)) message {
	enum msg_type type;
	unsigned char body[];
};

struct __attribute__((packed)) server_hello {
	uint32_t nonce;
	char peer_username[MAX_USERNAME_LEN + 1];
};

struct __attribute__((packed)) client_hello {
	uint32_t nonce;
	uint16_t game_port;
	char username[MAX_USERNAME_LEN + 1];
};

struct __attribute__((packed)) server_cert {
	uint32_t len;
	unsigned char cert[];
};

struct __attribute__((packed)) dhkey {
	uint32_t nonce;
	uint32_t len;
	unsigned char key[];
};

struct __attribute__((packed)) player_info {
	bool in_game;
	char username[MAX_USERNAME_LEN + 1];
};

struct __attribute__((packed)) player_list {
	uint32_t count;
	struct player_info players[];
};

struct __attribute__((packed)) chall_req {
	char player[MAX_USERNAME_LEN + 1];
};

struct __attribute__((packed)) player_details {
	char address[ADDRSTRLEN];
	uint16_t port;
	uint32_t nonce;
	uint32_t keylen;
	unsigned char key[];
};

struct __attribute__((packed)) chall_res {
	bool accept;
};

struct __attribute__((packed)) game_move {
	unsigned int column;
};

enum __attribute__((packed)) err_code {
	INVMSG, NOAUTH, INVSIG, GCMERR, INVMOVE
};

struct __attribute__((packed)) error {
	enum err_code code;
	unsigned char message[];
};

#define MSG_SIZE_OF(type)	(sizeof(struct message) + sizeof(type))

#endif /* COMMON_MESSAGES_H */

