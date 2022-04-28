#ifndef __MINOS_SLAB_H__
#define __MINOS_SLAB_H__

#include <minos/types.h>

void *malloc(size_t size);
void *zalloc(size_t size);
void free(void *addr);

void add_slab_mem(unsigned long base, size_t size);
void slab_init(void);

#endif
