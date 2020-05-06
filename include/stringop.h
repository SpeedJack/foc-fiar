#ifndef COMMON_STRINGOP_H
#define COMMON_STRINGOP_H

#include <stdbool.h>
#include <stdint.h>

extern void string_trim(char **pstr);
extern bool string_to_long(const char *str, long int *dest);
extern bool string_to_uint16(const char *str, uint16_t *dest);
extern bool string_to_int(const char *str, int *dest);

#endif /* COMMON_STRINGOP_H */
