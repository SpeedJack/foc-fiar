#ifndef COMMON_COUT_H
#define COMMON_COUT_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdarg.h>
#include <stddef.h>

extern void cout_vprintf_error(const char *format, va_list ap);
extern void cout_printf_error(const char *format, ...);
extern void cout_print_error(const char *errstr);
extern void cout_print_mem(const char *id, const void *mem, size_t len);
#ifdef DEBUG_CODE
extern void cout_enable_mem_debug();
#endif /* DEBUG_CODE */

#endif /* COMMON_COUT_H */
