#ifndef COMMON_MEM_H
#define COMMON_MEM_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stddef.h>

#ifdef DEBUG_CODE
void cout_enable_mem_debug(void);
void cout_print_alloc_counts(void);
#endif /* DEBUG_CODE */

void mem_dump(const char *addr, size_t len);

#endif /* COMMON_MEM_H */
