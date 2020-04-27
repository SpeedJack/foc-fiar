#ifndef CONNECT4_H
#define CONNECT4_H

#include <stdbool.h>

enum c4_result {
	OK,
	OK_FULL_BOARD,
	INVALID_COLUMN,
	FULL_COLUMN,
	OPPONENT_WIN,
	PLAYER_WIN
};

extern void c4_init(bool first_player);
extern void c4_print_board();
extern bool c4_is_my_turn();
extern enum c4_result c4_insert(int c);

#endif /* CONNECT4_H */
