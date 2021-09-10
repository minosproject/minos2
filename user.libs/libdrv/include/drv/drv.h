#ifndef __DRV_IO_H__
#define __DRV_IO_H__

#include <stdint.h>
#include <minos/types.h>

#define __isb()		asm volatile("isb" : : : "memory")
#define __dmb(opt)	asm volatile("dmb " #opt : : : "memory")
#define __dsb(opt)	asm volatile("dsb " #opt : : : "memory")

#define isb()		__isb();

#define mb()		__dsb(sy)
#define rmb()		__dsb(ld)
#define wmb()		__dsb(st)

#define dma_rmb()	__dmb(oshld)
#define dma_wmb()	__dmb(oshst)

#define iormb()		dma_rmb()
#define iowmb()		dma_wmb()

#define smp_mb()	__dmb(ish)
#define smp_rmb()	__dmb(ishld)
#define smp_wmb()	__dmb(ishst)

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

extern void *request_mmio_by_handle(int handle);
extern int request_irq_by_handle(int handle);
extern int request_pma(size_t memsize);

extern int get_mmio_handles(int argc, char **argv, int *handles, int cnt);
extern int get_irq_handles(int argc, char **argv, int *handles, int cnt);
extern int get_dma_handles(int argc, char **argv, int *handles, int cnt);

#endif
