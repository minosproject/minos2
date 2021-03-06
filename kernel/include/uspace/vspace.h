#ifndef __MINOS_VSPACE_H__
#define __MINOS_VSPACE_H__

#include <minos/mm.h>
#include <minos/types.h>
#include <minos/list.h>
#include <uspace/kobject.h>

#define HUGE_PAGE_SIZE		0x200000
#define HUGE_PAGE_SHIFT		21
#define IS_HUGE_ALIGN(x)	(!((unsigned long)(x) & (HUGE_PAGE_SIZE - 1)))

#define PROCESS_TOP_HALF_BASE	(USER_PROCESS_ADDR_LIMIT >> 1)
#define VMA_SHARED_BASE		PROCESS_TOP_HALF_BASE

#define pa2sva(phy)		((phy) + VMA_SHARED_BASE)
#define va2sva(va)		(pa2sva(vtop(va)))
#define va2pa(va)		vtop(va)
#define pa2va(pa)		ptov(pa)

/*
 * 0    - (256G - 1) user space memory region
 * 256G - (512G - 1) shared memory mapping space.
 *
 * 0    - ( 64G - 1) ELF (text data bss and other)
 * 64G -> (64G + 256M) heap area
 * 65G  - (255G - 1) VMAP area
 * ((256G - 32K - 4K) -> (256G - 4K)) stack
 *
 * system process can handle it heap by itself, the heap
 * region for system process if 64G --- 64G + 256M
 * kernel will handle the page fault for this heap region.
 */
#define SYS_PROC_HEAP_BASE	(64UL * 1024 * 1024 * 1024)
#define SYS_PROC_HEAP_SIZE	(256UL * 1024 * 1024)
#define SYS_PROC_HEAP_END	(SYS_PROC_HEAP_BASE + SYS_PROC_HEAP_SIZE)

#define SYS_PROC_VMAP_BASE	(65UL * 1024 * 1024 * 1024)
#define SYS_PROC_VMAP_END	(255UL * 1024 * 1024 * 1024)

#define MIN_ELF_LOAD_BASE	0x1000
#define ROOTSRV_USTACK_TOP	(PROCESS_TOP_HALF_BASE - PAGE_SIZE * 8)
#define ROOTSRV_USTACK_BOTTOM	(ROOTSRV_USTACK_TOP - ROOTSRV_USTACK_PAGES * PAGE_SIZE)
#define ROOTSRV_BOOTDATA_BASE	(PROCESS_TOP_HALF_BASE - PAGE_SIZE * 2)

int vspace_init(struct process *proc);

void vspace_deinit(struct process *proc);

int map_process_memory(struct process *proc,
		       unsigned long vaddr,
		       size_t size,
		       unsigned long phy,
		       unsigned long flags);

int unmap_process_memory(struct process *proc,
		unsigned long vaddr, size_t size);

unsigned long translate_va_to_pa(struct vspace *vs, unsigned long va);

void *uva_to_kva(struct vspace *vs, unsigned long va,
		size_t size, unsigned long right);

int handle_page_fault(unsigned long virt, int write, unsigned long flags);

void inc_vspace_usage(struct vspace *vs);
void dec_vspace_usage(struct vspace *vs);
void add_released_page_to_vspace(struct vspace *vs, unsigned long addr);

#endif
