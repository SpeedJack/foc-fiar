#include "mem.h"
#include "stringop.h"
#include <openssl/bio.h>

#ifdef DEBUG_CODE
#include <openssl/crypto.h>

static unsigned int malloc_count = 0;
static unsigned int realloc_count = 0;
static unsigned int free_count = 0;
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
	if (addr == NULL)
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
	if (addr != NULL)
		total_free++;
	free(addr);
	if (addr != NULL && !string_starts_with(file, "crypto/")) {
		free_count++;
		fprintf(stderr, "[MEMDBG] %s:%d: called free(%p)\n", file, line, addr);
	}
}

void cout_enable_mem_debug(void)
{
	CRYPTO_set_mem_functions(malloc_wrapper, realloc_wrapper, free_wrapper);
}

void cout_print_alloc_counts(void)
{
	fprintf(stderr, "[MEMDBG] malloc_count = %u, realloc_count = %u, free_count = %u\n",
		malloc_count, realloc_count, free_count);
	fprintf(stderr, "[MEMDBG] total_malloc = %u, total_realloc = %u, total_free = %u\n",
		total_malloc, total_realloc, total_free);
}
#endif /* DEBUG_CODE */

#define MAX_DUMP_SIZE (1<<16)

void mem_dump(const char *addr, size_t len)
{
	BIO_dump_fp(stderr, addr, len > MAX_DUMP_SIZE ? MAX_DUMP_SIZE : len);
	if (len > MAX_DUMP_SIZE)
		fprintf(stderr, "... Truncated (too long) ... (total size: %#lx)\n", len);
}
