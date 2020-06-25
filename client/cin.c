#include "client/cin.h"
#include "cout.h"
#include "stringop.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

/*
 * Flushes the stdin buffer by reading all characters remaining in it and
 * returns the total number of characters read. The caller must be sure that
 * something is in the buffer, or the function will stuck on getchar() call.
 */
unsigned int cin_flush_stdin(void)
{
	char c;
	unsigned int len;

	for (len = 0; (c = getchar()) != '\n' && c != EOF; len++)
		;
	return len;
}

/*
 * Reads a line from stdin without the terminating newline. The functions saves
 * the string read in the memory area pointed by buffer and returns the total
 * number of characters typed (may be greater than size). If more that size
 * characters are read, the input is truncated and the rest of stdin is flushed.
 * The function guarantees that the resulting string is always null-terminated.
 */
int cin_read_line(char *buffer, int size)
{
	if (size <= 0 || fgets(buffer, size, stdin) == NULL)
		return -1;
	unsigned int len = strlen(buffer);
	if (buffer[len-1] == '\n')
		buffer[len-1] = '\0';
	else
		len += cin_flush_stdin();
	return len - 1;
}

/* Reads a non-blank character from stdin and flushes the rest of the buffer. */
char cin_read_char(void)
{
	int c;
	do {
		c = getchar();
		if ((char)c == '\n')
			return (char)c;
		if (c == EOF)
			return '\0';
	} while (isspace(c));

	cin_flush_stdin();
	return (char)c;
}

char read_command(char prompt, char *params, cmd_validity_cb *validity_cb)
{
	char cmd[MAX_CMD_SIZE];
	do {
		putchar(prompt);
		putchar(' ');
		fflush(stdout);
		int len = cin_read_line(cmd, MAX_CMD_SIZE);
		if (len < 0) {
			cout_print_error("Reached EOF.");
			return 'q';
		}
		if (len == 0) {
			cout_print_error("Type a command.");
			continue;
		}
		if (len > MAX_CMD_SIZE - 1) {
			cout_print_error("Command is too long.");
			continue;
		}
		char *pcmd = &cmd[0];
		string_trim(&pcmd);
		if (!validity_cb(cmd)) {
			cout_print_error("Invalid command.");
			continue;
		}
		*params = '\0';
		char *end = strchr(cmd, ' ');
		char *pars = NULL;
		if (end) {
			*end = '\0';
			pars = end + 1;
			string_trim(&pars);
			strcpy(params, pars);
		}
		return tolower(cmd[0]);
	} while(true);
}

char *ask_password(const char *prompt)
{
	static char buffer[256];
	struct termios tio;
	printf("%s: ", prompt);
	fflush(stdout);
	tcgetattr(STDIN_FILENO, &tio);
	tio.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &tio);
	char *pbuf = buffer;
	if (cin_read_line(buffer, 256) > 256) {
		cout_print_error("Passwords longer than 256 characters are not supported.");
		pbuf = NULL;
	}
	tio.c_lflag &= ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &tio);
	return pbuf;
}
