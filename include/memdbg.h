#ifndef COMMON_MEMDBG_H
#define COMMON_MEMDBG_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifdef ENABLE_MEMDBG
#include <stddef.h>

extern void _memdbg_enable_debug(void);
extern void _memdbg_print_alloc_counts(void);
extern void _memdbg_dump(const char *id, const void *mem, size_t len);
extern void _memdbg_register_alloc(const void *addr, size_t num, const char *file, int line);

#define memdbg_enable_debug()			_memdbg_enable_debug()
#define memdbg_print_alloc_counts()		_memdbg_print_alloc_counts()
#define memdbg_dump(id, mem, len)		_memdbg_dump(id, mem, len)
#define memdbg_register_alloc(addr, num)	_memdbg_register_alloc(addr, num > 0 ? num : 0, __FILE__, __LINE__)

#else

#define memdbg_enable_debug()			while(0) continue
#define memdbg_print_alloc_counts()		while(0) continue
#define memdbg_dump(id, mem, len)		while(0) continue
#define memdbg_register_alloc(addr, num)	while(0) continue

#endif /* ENABLE_MEMDBG */

#endif /* COMMON_MEMDBG_H */
