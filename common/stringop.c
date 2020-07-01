#include "stringop.h"
#include "assertions.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

char *string_to_lower(char *str)
{
	for (char *c = str; *c != '\0'; c++)
		*c = tolower(*c);
	return str;
}

/*
 * Removes all blank characters at the beginning and the end of the specified
 * string.
 */
void string_trim(char **pstr)
{
	assert(pstr && *pstr);
	char *str = *pstr;
	while (isspace((int)*str)) ++str;
	*pstr = str;

	if (*str == '\0')
		return;

	char *end;
	for (end = str + strlen(str) - 1; end >= str && isspace((int)*end); --end)
		;
	*(++end) = '\0';
}

/*
 * Converts the string pointed by str to a long int and saves the result in the
 * memory area pointed by dest. Returns true on success, otherwise false.
 */
bool string_to_long(const char *str, long int *dest)
{
	assert(str && dest);
	char *endptr = NULL;

	errno = 0;
	*dest = strtol(str, &endptr, 0);

	return !errno && (!endptr || *endptr == '\0');
}

bool string_to_uint16(const char *str, uint16_t *dest)
{
	assert(str && dest);
	long int value;
	if (!string_to_long(str, &value))
		return false;
	*dest = value;
	return value >= 0 && value < (1 << 16);
}

bool string_to_int(const char *str, int *dest)
{
	assert(str && dest);
	long int value;
	if (!string_to_long(str, &value))
		return false;
	*dest = value;
	return value >= INT_MIN && value <= INT_MAX;
}

bool string_contains(const char *haystack, const char needle)
{
	assert(haystack);
	for (const char *c = haystack; *c != '\0'; c++)
		if (*c == needle)
			return true;
	return false;
}

bool string_starts_with(const char *str, const char *prefix)
{
	if (!str || !prefix)
		return false;
	size_t prefixlen = strlen(prefix);
	if (strlen(str) < prefixlen)
		return false;
	for (unsigned int i = 0; i < prefixlen; i++)
		if (str[i] != prefix[i])
			return false;
	return true;
}

bool string_ends_with(const char *str, const char *suffix)
{
	if (!str || !suffix)
		return false;
	size_t suffixlen = strlen(suffix);
	size_t stringlen = strlen(str);
	if (stringlen < suffixlen)
		return false;
	for (unsigned int i = 0; i < suffixlen; i++)
		if (str[stringlen - i - 1] != suffix[suffixlen - i - 1])
			return false;
	return true;
}
