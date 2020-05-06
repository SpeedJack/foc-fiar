#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "cout.h"

#define COLOR_ERROR	"\033[1;31m"
#define COLOR_RESET	"\033[0m"


/* If ENABLE_COLORS is defined, enable output coloring on stderr. */
static inline void __print_error_color()
{
#ifdef ENABLE_COLORS
	fputs(COLOR_ERROR, stderr);
#endif
}

/* Resets output color on stderr. */
static inline void __reset_color()
{
#ifdef ENABLE_COLORS
	fputs(COLOR_RESET, stderr);
#endif
}

void cout_vprintf_error(const char *format, va_list ap)
{
	__print_error_color();
	vfprintf(stderr, format, ap);
	__reset_color();
	fputs("\n", stderr);
}

/* Formats and prints an error. */
void cout_printf_error(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	cout_vprintf_error(format, args);
}

/*
 * Prints an error. If errno is non-zero, the function appends a description of
 * the error code to the message.
 */
void cout_print_error(const char *errstr, int errno)
{
	if (errno)
		cout_printf_error("%s: %s", errstr, strerror(errno));
	else
		cout_printf_error("%s", errstr);
}

