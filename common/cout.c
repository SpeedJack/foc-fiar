#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "cout.h"
#include "stringop.h"
#include <openssl/bio.h>
#include <stdio.h>
#include <string.h>

#define COLOR_ERROR		"\033[1;31m"
#define COLOR_RESET		"\033[0m"

#ifdef ENABLE_COLORS
#define PRINT_COLOR(color)	fputs(color, stderr)
#else
#define PRINT_COLOR(color)	while(0) continue
#endif /* ENABLE_COLORS */

void cout_vprintf_error(const char *format, va_list ap)
{
	PRINT_COLOR(COLOR_ERROR);
	vfprintf(stderr, format, ap);
	PRINT_COLOR(COLOR_RESET);
}

/* Formats and prints an error. */
void cout_printf_error(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	cout_vprintf_error(format, args);
}

void cout_print_error(const char *errstr)
{
	PRINT_COLOR(COLOR_ERROR);
	fputs(errstr, stderr);
	PRINT_COLOR(COLOR_RESET);
	fputs("\n", stderr);
}
