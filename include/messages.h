#ifndef COMMON_MESSAGES_H
#define COMMON_MESSAGES_H

#include "error.h"
#include <stdbool.h>
#include <stdint.h>

#define ADDRSTRLEN		46	/* = INET6_ADDRSTRLEN */
#define MAX_USERNAME_LEN	31

enum __attribute__((packed)) msg_type {
	CLIENT_HELLO, SERVER_HELLO, SERVER_CERT, DHKEY,
	PLAYER_LIST_REQ, PLAYER_LIST,
	CHALLENGE_REQ, CHALLENGE_RES, CLIENT_INFO,
	GAME_MOVE, GAME_MOVE_ACK, GAME_END,
	ERROR
};

struct __attribute__((packed)) server_hello {
	char peer_username[MAX_USERNAME_LEN + 1];
};

struct __attribute__((packed)) client_hello {
	char username[MAX_USERNAME_LEN + 1];
	uint16_t game_port;
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

struct __attribute__((packed)) user {
	char username[MAX_USERNAME_LEN + 1];
	bool in_game;
};

struct __attribute__((packed)) user_list {
	uint32_t count;
	struct user users[];
};

struct __attribute__((packed)) chall_req {
	char username[MAX_USERNAME_LEN + 1];
};

struct __attribute__((packed)) client_info {
	char address[ADDRSTRLEN];
	uint16_t game_port;
	uint32_t dhnonce;
	uint32_t keylen;
	unsigned char key[];
};

struct __attribute__((packed)) chall_res {
	bool accept;
};

struct __attribute__((packed)) game_move {
	unsigned int column;
};

struct __attribute__((packed)) error {
	enum error_code code;
	char message[];
};

#endif /* COMMON_MESSAGES_H */
