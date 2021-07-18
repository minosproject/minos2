#ifndef __MINOS_SLAB_H__
#define __MINOS_SLAB_H__

#include <minos/kmem.h>

struct slab_header {
	unsigned long size;
	union {
		unsigned long magic;
		struct slab_header *next;
	};
};

void *malloc(size_t size);
void *zalloc(size_t size);
void free(void *addr);

void add_slab_mem(unsigned long base, size_t size);
void slab_init(void);

#define zalloc_static(size)	zalloc_kmem(size)
#define malloc_static(size)	alloc_kmem(size)

#endif
