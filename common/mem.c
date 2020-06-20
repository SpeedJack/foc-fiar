#include "mem.h"

#ifdef DEBUG_CODE
#include "stringop.h"
#include <openssl/bio.h>
#include <string.h>
#include <openssl/crypto.h>

static unsigned int malloc_count = 0;
static unsigned int realloc_count = 0;
static unsigned int free_count = 0;
static unsigned int other_alloc_count = 0;
static unsigned int total_malloc = 0;
static unsigned int total_realloc = 0;
static unsigned int total_free = 0;

static void *malloc_wrapper(size_t num, const char *file, int line)
{
	if (num == 0)
		return NULL;
	total_malloc++;
	void *ret = malloc(num);
	if (!string_starts_with(file, "crypto/")) {
		malloc_count++;
		fprintf(stderr, "[MEMDBG] %s:%d: called malloc(%lu): %p\n", file, line, num, ret);
	}
	return ret;
}

static void *realloc_wrapper(void *addr, size_t num, const char *file, int line)
{
	if (!addr)
		return CRYPTO_malloc(num, file, line);
	if (num == 0) {
		CRYPTO_free(addr, file, line);
		return NULL;
	}
	total_realloc++;
	void *ret = realloc(addr, num);
	if (!string_starts_with(file, "crypto/")) {
		realloc_count++;
		fprintf(stderr, "[MEMDBG] %s:%d: called realloc(%p, %lu): %p\n", file, line, addr, num, ret);
	}
	return ret;
}

static void free_wrapper(void *addr, const char *file, int line)
{
	if (addr)
		total_free++;
	free(addr);
	if (addr && !string_starts_with(file, "crypto/")) {
		free_count++;
		fprintf(stderr, "[MEMDBG] %s:%d: called free(%p)\n", file, line, addr);
	}
}

void _mem_enable_debug(void)
{
	CRYPTO_set_mem_functions(malloc_wrapper, realloc_wrapper, free_wrapper);
}

void _mem_print_alloc_counts(void)
{
	fprintf(stderr, "[MEMDBG] malloc_count = %u (+%u), realloc_count = %u, free_count = %u\n",
		malloc_count, other_alloc_count, realloc_count, free_count);
	fprintf(stderr, "[MEMDBG] total_malloc = %u, total_realloc = %u, total_free = %u\n",
		total_malloc, total_realloc, total_free);
}

#define MAX_DUMP_SIZE (1<<16)

void _mem_dump(const char *id, const void *mem, size_t len)
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
	BIO_dump_fp(stderr, (const char *)mem, len > MAX_DUMP_SIZE ? MAX_DUMP_SIZE : len);
	if (len > MAX_DUMP_SIZE)
		fprintf(stderr, "... Truncated (too long) ... (total size: %#lx)\n", len);
	for (unsigned int i = 0; i < 73; i++)
		putc('=', stderr);
	fputs("\n", stderr);
}

void _mem_register_alloc(const void *addr, size_t num, const char *file, int line)
{
	if (num == 0 || !addr)
		return;
	other_alloc_count++;
	fprintf(stderr, "[MEMDBG] %s:%d: called alloc(%lu): %p via a library function.\n",
		file, line, num, addr);
}

#endif /* DEBUG_CODE */
