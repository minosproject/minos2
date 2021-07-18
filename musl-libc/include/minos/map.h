#ifndef __LIBC_MAP_H__
#define __LIBC_MAP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

int map(handle_t proc, handle_t pma, unsigned long base,
		size_t size, right_t right);
int unmap(handle_t proc, handle_t pma, unsigned long base, size_t size);

#ifdef __cplusplus
}
#endif

#endif
