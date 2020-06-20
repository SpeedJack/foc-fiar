#ifndef COMMON_COUT_H
#define COMMON_COUT_H

#include <stdarg.h>
#include <stddef.h>

extern void cout_vprintf_error(const char *format, va_list ap);
extern void cout_printf_error(const char *format, ...);
extern void cout_print_error(const char *errstr);

#endif /* COMMON_COUT_H */
