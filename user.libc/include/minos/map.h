#ifndef __LIBC_MAP_H__
#define __LIBC_MAP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

int sys_map(int proc, int pma, unsigned long base, size_t size, int right);

int sys_unmap(int proc, int pma, unsigned long base, size_t size);

#ifdef __cplusplus
}
#endif

#endif
