#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "client/cin.h"

unsigned int cin_flush_stdin()
{
	char c;
	unsigned int len;

	for (len = 0; (c = getchar()) != '\n' && c != EOF; len++)
		;
	return len;
}

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

char cin_read_char()
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
