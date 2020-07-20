#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "client/cin.h"
#include "cout.h"
#include "stringop.h"
#include <openssl/crypto.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif /* HAVE_TERMIOS_H */

#if defined _WIN32 || __CYGWIN__
#include <windows.h>
#endif /* defined _WIN32 || __CYGWIN__ */

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

int cin_read_uint(void)
{
	char buf[5];
	int res = -1;
	do {
		int len = cin_read_line(buf, 5);
		if (len < 0) {
			cout_print_error("Reached EOF.");
			return -1;
		}
		if (len > 4) {
			cout_print_error("Too long input.");
			continue;
		}
		if (!string_to_int(buf, &res))
			continue;
		if (res < 0) {
			cout_print_error("Inserted value must be positive.");
			continue;
		}
	} while (false);
	return res;
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

bool cin_ask_question(bool default_yes, const char *question, ...)
{
	va_list args;
	va_start(args, question);
	char c;
	do {
		va_list ap;
		va_copy(ap, args);
		vprintf(question, args);
		va_end(ap);
		printf(" [%c/%c] ", default_yes ? 'Y' : 'y', default_yes ? 'n' : 'N');
		fflush(stdout);
		c = cin_read_char();
		if (c == '\n')
			c = default_yes ? 'y' : 'n';
	} while (c != 'y' && c != 'n' && c != 'Y' && c != 'N');
	va_end(args);
	return c == 'y' || c == 'Y';
}

char cin_read_command(char *params, cmd_validity_cb *validity_cb)
{
	char buf[MAX_CMD_SIZE];
	char *cmd = buf;
	do {
		int len = cin_read_line(cmd, MAX_CMD_SIZE);
		if (len < 0) {
			cout_print_error("Reached EOF.");
			return 'q';
		}
		if (len == 0)
			return '?';
		if (len > MAX_CMD_SIZE - 1) {
			cout_print_error("Command is too long.");
			return '?';
		}
		string_trim(&cmd);
		*params = '\0';
		char *end = strchr(cmd, ' ');
		char *pars = NULL;
		if (end) {
			*end = '\0';
			pars = end + 1;
			string_trim(&pars);
			strcpy(params, pars);
		}
		if (!validity_cb(cmd, strlen(params) > 0))
			return '?';
		return tolower(*cmd);
	} while(true);
}

static void echo_on(void)
{
#ifdef _WIN32
	DWORD mode;
	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
	if (GetConsoleMode(h, &mode)) {
		mode |= ENABLE_ECHO_INPUT;
		SetConsoleMode(h, mode);
	}
#elif defined HAVE_TERMIOS_H
	struct termios tio;
	tcgetattr(STDIN_FILENO, &tio);
	tio.c_lflag |= ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &tio);
#else
	return;
#endif
}

static void echo_off(void)
{
#ifdef _WIN32
	DWORD mode;
	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
	if (GetConsoleMode(h, &mode)) {
		mode &= ~ENABLE_ECHO_INPUT;
		SetConsoleMode(h, mode);
	}
#elif defined HAVE_TERMIOS_H
	struct termios tio;
	tcgetattr(STDIN_FILENO, &tio);
	tio.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &tio);
#else
	return;
#endif
}

char *cin_ask_passphrase(const char *username, int size)
{
	char *buffer = OPENSSL_malloc(size);
	if (!buffer) {
		cout_print_error("Can not allocate space for pass phrase.");
		return NULL;
	}
	do {
		printf("Enter pass phrase for \"%s\": ", username);
		fflush(stdout);
		echo_off();
		int len = cin_read_line(buffer, size);
		echo_on();
		if (len > size - 1) {
			cout_printf_error("Passwords longer than %d characters are not supported.", size - 1);
			continue;
		}
		if (len == 0) {
			cout_print_error("Password is required.");
			continue;
		}
		if (len < 0) {
			cout_print_error("Reached EOF.");
			OPENSSL_clear_free(buffer, size);
			return NULL;
		}
		break;
	} while(true);
	return buffer;
}
