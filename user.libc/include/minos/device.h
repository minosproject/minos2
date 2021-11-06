#ifndef __LIBC_DEVICE_H__
#define __LIBC_DEVICE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <minos/types.h>
#include <minos/barrier.h>

#define WRITE32(_reg, _val)                                                    \
	do {                                                                   \
		register uint32_t __myval__ = (_val);                          \
		*(volatile uint32_t *)&(_reg) = __myval__;                     \
	} while (0)
#define WRITE64(_reg, _val)                                                    \
	do {                                                                   \
		register uint64_t __myval__ = (_val);                          \
		*(volatile uint64_t *)&(_reg) = __myval__;                     \
	} while (0)
#define READ32(_reg) (*(volatile uint32_t *)&(_reg))
#define READ64(_reg) (*(volatile uint64_t *)&(_reg))

int request_irq_by_handle(int handle);
int request_consequent_pma(size_t memsize, int right);
void *request_mmio_by_handle(int handle);
int get_device_mmio_handle(const char *comp, int index);
int get_device_irq_handle(const char *comp, int index);

#ifdef __cplusplus
}
#endif

#endif
