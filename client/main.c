#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "client/connect4.h"

/* ./client [<seed>] */
int main(int argc, char **argv)
{
	time_t t;
	if (argc < 2)
		time(&t);
	else
		t = (time_t) strtoul(argv[1], NULL, 0);
	srand((unsigned int) t);

	c4_init(true);
	c4_print_board();

	enum c4_result result;
	while (result != OK_FULL_BOARD && result < 4) {
		int c = (rand() % 7) + 1;
		printf("Inserting %d...\n", c);
		result = c4_insert(c);
		c4_print_board();
		if (result == FULL_COLUMN)
			puts("Full column: retry");
	}

	if (result > 3)
		printf("WINNER: %s\n", result == PLAYER_WIN ? "YOU (X)" : "OPPONENT (O)");
	if (result == OK_FULL_BOARD)
		puts("FULL BOARD!"); /* USE SEED = 1588029060 */

	printf("\nSEED: %u\n", (unsigned int) t);

	return 0;
}

