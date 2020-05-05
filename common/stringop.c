#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "stringop.h"

void string_trim(char **pstr)
{
	char *str = *pstr;
	while (isspace((int)*str)) ++(str);
	*pstr = str;

	if (*str == '\0')
		return;

	char *end;
	for (end = str + strlen(str) - 1; end > str
			&& isspace((int)*end); --end)
		;
	*(++end) = '\0';
}

bool string_to_long(char *str, long int *dest)
{
	char *endptr = NULL;
	string_trim(&str);

	errno = 0;
	*dest = strtol(str, &endptr, 0);

	return !errno && (!endptr || *endptr == '\0');
}
