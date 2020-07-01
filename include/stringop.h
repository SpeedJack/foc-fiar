#ifndef COMMON_STRINGOP_H
#define COMMON_STRINGOP_H

#include <stdbool.h>
#include <stdint.h>

extern char *string_to_lower(char *str);
extern void string_trim(char **pstr);
extern bool string_to_long(const char *str, long int *dest);
extern bool string_to_uint16(const char *str, uint16_t *dest);
extern bool string_to_int(const char *str, int *dest);
extern bool string_contains(const char *haystack, const char needle);
extern bool string_starts_with(const char *str, const char *prefix);
extern bool string_ends_with(const char *str, const char *suffix);

#endif /* COMMON_STRINGOP_H */
