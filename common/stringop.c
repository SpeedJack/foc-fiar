#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "stringop.h"

/*
 * Removes all blank characters at the beginning and the end of the specified
 * string.
 */
void string_trim(char **pstr)
{
	char *str = *pstr;
	while (isspace((int)*str)) ++(str);
	*pstr = str;

	if (*str == '\0')
		return;

	char *end;
	for (end = str + strlen(str); end > str && isspace((int)*end); --end)
		;
	*(++end) = '\0';
}

/*
 * Converts the string pointed by str to a long int and saves the result in the
 * memory area pointed by dest. Returns true on success, otherwise false.
 */
bool string_to_long(const char *str, long int *dest)
{
	char *endptr = NULL;

	errno = 0;
	*dest = strtol(str, &endptr, 0);

	return !errno && (!endptr || *endptr == '\0');
}

bool string_to_uint16(const char *str, uint16_t *dest)
{
	long int value;
	if (!string_to_long(str, &value))
		return false;
	*dest = value;
	return value >= 0 && value < (1 << 16);
}

bool string_to_int(const char *str, int *dest)
{
	long int value;
	if (!string_to_long(str, &value))
		return false;
	*dest = value;
	return value >= INT_MIN && value <= INT_MAX;
}
