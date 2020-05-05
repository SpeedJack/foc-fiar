#ifndef COMMON_STRINGOP_H
#define COMMON_STRINGOP_H

#include <stdbool.h>

extern void string_trim(char **pstr);
extern bool string_to_long(char *str, long int *dest);

#endif /* COMMON_STRINGOP_H */

