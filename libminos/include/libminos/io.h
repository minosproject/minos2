#ifndef __VIRTIO_BLK_IO_H__
#define __VIRTIO_BLK_IO_H__

#include <stdint.h>
#include <minos/types.h>

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

void *request_mmio(handle_t handle);
int request_irq(handle_t handle);

#endif
