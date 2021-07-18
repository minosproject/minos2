#ifndef __MINOS_KMEM_H__
#define __MINOS_KMEM_H__

void *alloc_kmem(size_t size);
void *zalloc_kmem(size_t size);
void *alloc_kpages(int pages);
void kmem_init(void);

#endif
