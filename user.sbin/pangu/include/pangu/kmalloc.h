#ifndef __LIBC_KMALLOC_H__
#define __LIBC_KMALLOC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>

void *kmalloc(size_t size);
void kfree(void *mem);
void *kzalloc(size_t size);

void *get_pages(int pages);
void free_pages(void *mem);

static inline void *get_page(void)
{
	return get_pages(1);
}

int kmalloc_init(unsigned long base, unsigned long end);

#ifdef __cplusplus
}
#endif

#endif
