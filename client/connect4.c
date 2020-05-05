#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <string.h>
#include "client/connect4.h"

#ifdef ENABLE_COLORS
#define COLOR_RESET	"\033[0m"
#define COLOR_BOLD_RED	"\033[1;31m"
#define COLOR_BOLD_BLUE	"\033[1;34m"
#else
#define COLOR_RESET	""
#endif /* ENABLE_COLORS */

#define BOARD_ROWS	6
#define BOARD_COLS	7

#define PLAYER		'X'
#define OPPONENT	'O'
#define EMPTY		' '

#define BOARD_VLINE	"|"
#define BOARD_HLINE	"---"
#define BOARD_CROSS	"+"

#define C4_COUNT(row, col) {					\
			if (board[row][col] != player) break;	\
			if (++count == 4) return true;		\
		}

static unsigned int total_inserts;
static char current_player;
static char board[BOARD_ROWS][BOARD_COLS];

/* If ENABLE_COLORS is set, returns the color associated with the player. */
static inline const char *get_color(char player)
{
#ifdef ENABLE_COLORS
	switch (player) {
		case PLAYER:
			return COLOR_BOLD_BLUE;
		case OPPONENT:
			return COLOR_BOLD_RED;
	}
#endif /* ENABLE_COLORS */

	return "";
}

/*
 * Checks the board for win. row and column must be set to the position of the
 * latest disc inserted.
 */
static bool check_four(int row, int col)
{
	if (total_inserts < 7)
		return false;

	char player = board[row][col];
	int count;

	/* NW <--> SE */
	count = 1;
	for (int r = row + 1, c = col + 1; r < BOARD_ROWS
			&& c < BOARD_COLS; ++r, ++c)	/* NW --> SE */
		C4_COUNT(r, c);
	for (int r = row - 1, c = col - 1; r >= 0
			&& c >= 0; --r, --c)		/* NW <-- SE */
		C4_COUNT(r, c);

	/* SO <--> NE */
	count = 1;
	for (int r = row + 1, c = col - 1; r < BOARD_ROWS
			&& c >= 0; ++r, --c)		/* SO <-- NE */
		C4_COUNT(r, c);
	for (int r = row - 1, c = col + 1; r >= 0
			&& c < BOARD_COLS; --r, ++c)	/* SO --> NE */
		C4_COUNT(r, c);

	/* W <--> E */
	count = 1;
	for (int c = col + 1; c < BOARD_COLS; ++c)	/* W --> E */
		C4_COUNT(row, c);
	for (int c = col - 1; c >= 0; --c)		/* W <-- E */
		C4_COUNT(row, c);

	/* N --> S */
	count = 1;
	for (int r = row + 1; r < BOARD_ROWS; ++r)	/* N --> S */
		C4_COUNT(r, col);

	return false;
}

/* Switches the current active player. */
static inline void switch_player()
{
	current_player = c4_is_my_turn() ? OPPONENT : PLAYER;
}

/*
 * Returns true if it's the turn of the user running the application;
 * false otherwise.
 */
bool c4_is_my_turn()
{
	return current_player == PLAYER;
}

/* Returns true if the board is full; false otherwise. */
bool c4_board_full()
{
	return total_inserts == BOARD_ROWS*BOARD_COLS;
}


/* Returns the total number of disc inserted. */
unsigned int c4_total_inserts()
{
	return total_inserts;
}

/*
 * Initializes/Restarts the game. first_player specifies if the user running the
 * application is the first player to move.
 */
void c4_init(bool first_player)
{
	current_player = first_player ? PLAYER : OPPONENT;
	total_inserts = 0;
	memset(board, EMPTY, sizeof(board));
}

/* Prints the board. */
void c4_print_board()
{
	printf("\n ");
	for (int c = 0; c < BOARD_COLS;)
		printf(" %d  ", ++c);

	for (int r = 0; r < BOARD_ROWS; ++r) {
		printf("\n" BOARD_VLINE);
		for (int c = 0; c < BOARD_COLS; ++c)
			printf(" %s%c%s %s", get_color(board[r][c]),
				board[r][c], COLOR_RESET, BOARD_VLINE);

		printf("\n" BOARD_CROSS);
		for (int c = 0; c < BOARD_COLS; ++c)
			printf(BOARD_HLINE BOARD_CROSS);
	}

	puts("\n");
}

/*
 * Inserts a disc in the specified column. The insertion is made by the
 * currently active player.
 */
enum c4_result c4_insert(int c)
{
	if (total_inserts == BOARD_ROWS*BOARD_COLS)
		return FULL_BOARD;
	if (c < 0 || c > BOARD_COLS)
		return INVALID_COLUMN;
	c--;

	int r;
	for (r = BOARD_ROWS - 1; r >= 0; --r)
		if (board[r][c] == EMPTY) {
			board[r][c] = current_player;
			break;
		}
	if (r == -1)
		return FULL_COLUMN;

	total_inserts++;

	if (check_four(r, c))
		return current_player == PLAYER ? PLAYER_WIN : OPPONENT_WIN;

	switch_player();
	return c4_board_full() ? OK_FULL_BOARD : OK;
}

/*
 * Removes a disc from the specified column. This also switches back the current
 * player. Returns true if the disc has been successfully removed; false
 * otherwise.
 */
bool c4_remove(int c)
{
	if (total_inserts == 0)
		return false;
	c--;

	int r;
	for (r = 0; r < BOARD_ROWS; ++r)
		if (board[r][c] != EMPTY) {
			board[r][c] = EMPTY;
			break;
		}
	if (r == BOARD_ROWS)
		return false;

	total_inserts--;
	switch_player();
	return true;
}
