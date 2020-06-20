#ifndef COMMON_MEM_H
#define COMMON_MEM_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifdef DEBUG_CODE
#include <stddef.h>

void _mem_enable_debug(void);
void _mem_print_alloc_counts(void);
void _mem_dump(const char *id, const void *mem, size_t len);
void _mem_register_alloc(const void *addr, size_t num, const char *file, int line);

#define mem_enable_debug()		_mem_enable_debug()
#define mem_print_alloc_counts()	_mem_print_alloc_counts()
#define mem_dump(id, mem, len)		_mem_dump(id, mem, len)
#define mem_register_alloc(addr, num)	_mem_register_alloc(addr, num > 0 ? num : 0, __FILE__, __LINE__)

#else

#define mem_enable_debug()		while(0) continue;
#define mem_print_alloc_counts()	while(0) continue;
#define mem_dump(id, mem, len)		while(0) continue;
#define mem_register_alloc(addr, num)	while(0) continue;

#endif /* DEBUG_CODE */

#endif /* COMMON_MEM_H */
