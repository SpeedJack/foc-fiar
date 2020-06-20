#include "cout.h"
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

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
	__print_error_color();
	fputs(errstr, stderr);
	__reset_color();
	fputs("\n", stderr);
}

void cout_print_mem(const char *id, const void *mem, size_t len)
{
	size_t idlen = strlen(id);
	for (unsigned int i = 0; i < 35 - idlen/2; i++)
		putc('=', stderr);
	putc(' ', stderr);
	fputs(id, stderr);
	putc(' ', stderr);
	for (unsigned int i = 0; i < 36 - idlen/2 - (idlen % 2); i++)
		putc('=', stderr);
	fputs("\n", stderr);
	BIO_dump_fp(stderr, (const char *)mem, len);
	for (unsigned int i = 0; i < 73; i++)
		putc('=', stderr);
	fputs("\n", stderr);
}

#ifdef DEBUG_CODE
static void *malloc_wrapper(size_t num, const char *file, int line)
{
	void *ret = CRYPTO_malloc(num, file, line);
	fprintf(stderr, "[MEMDBG] %s:%d: called malloc(%lu): %p\n", file, line, num, ret);
	return ret;
}

static void *realloc_wrapper(void *addr, size_t num, const char *file, int line)
{
	void *ret = CRYPTO_realloc(addr, num, file, line);
	fprintf(stderr, "[MEMDBG] %s:%d: called realloc(%p, %lu): %p\n", file, line, addr, num, ret);
	return ret;
}

static void free_wrapper(void *addr, const char *file, int line)
{
	CRYPTO_free(addr, file, line);
	fprintf(stderr, "[MEMDBG] %s:%d: called free(%p)\n", file, line, addr);
}

void cout_enable_mem_debug()
{
	CRYPTO_set_mem_functions(malloc_wrapper, realloc_wrapper, free_wrapper);
}
#endif /* DEBUG_CODE */
