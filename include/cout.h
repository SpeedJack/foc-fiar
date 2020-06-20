#ifndef COMMON_COUT_H
#define COMMON_COUT_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#else
#define NDEBUG		1
#endif /* HAVE_CONFIG_H */

#include <stdarg.h>

extern void cout_vprintf_error(const char *format, va_list ap);
extern void cout_printf_error(const char *format, ...);
extern void cout_print_error(const char *errstr);
#ifndef NDEBUG
extern void cout_enable_mem_debug();
#endif /* NDEBUG */

#endif /* COMMON_COUT_H */
