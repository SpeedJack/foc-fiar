#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define COLOR_ERROR	"\033[1;31m"
#define COLOR_RESET	"\033[0m"


static inline void __print_error_color()
{
#ifdef ENABLE_COLORS
	fputs(COLOR_ERROR, stderr);
#endif
}

static inline void __reset_color()
{
#ifdef ENABLE_COLORS
	fputs(COLOR_RESET, stderr);
#endif
}

void cout_print_error(const char *errstr, int errno)
{
	__print_error_color();
	fputs(errstr, stderr);
	if (errno)
		fprintf(stderr, ": %s", strerror(errno));
	__reset_color();
	fputs("\n", stderr);
}

void cout_printf_error(const char *format, ...)
{
	va_list args;
	va_start(args, format);

	__print_error_color();
	vfprintf(stderr, format, args);
	__reset_color();
	fputs("\n", stderr);
}

