#ifndef __PANGU_VMA_H__
#define __PANGU_VMA_H__

#include <minos/types.h>
#include <minos/list.h>

#define VMA_PERM_R	(1 << 0)
#define VMA_PERM_W	(1 << 1)
#define VMA_PERM_X	(1 << 2)

#define VMA_PERM_RW	(VMA_PERM_R | VMA_PERM_W)
#define VMA_PERM_RO	(VMA_PERM_R)
#define VMA_PERM_RWX	(VMA_PERM_R | VMA_PERM_W | VMA_PERM_X)

/*
 * total 512G address space for process.
 * 256G - 512G for kernel use to map shared memory
 * 255G - 256G stack for process. (4k is reserve).
 * 0 - 4k reserve
 */
#define PROCESS_ADDR_TOP	((1UL << 38) - PAGE_SIZE)
#define PROCESS_ADDR_BOTTOM	(PAGE_SIZE)

#define PROCESS_STACK_TOP	(PROCESS_ADDR_TOP)
#define PROCESS_STACK_SIZE	(1UL * 1024 * 1024 * 1024 - PAGE_SIZE)
#define PROCESS_STACK_INIT_SIZE	(8 * 4096)
#define PROCESS_STACK_INIT_BASE	(PROCESS_ADDR_TOP - PROCESS_STACK_INIT_SIZE)
#define PROCESS_STACK_BASE	(PROCESS_ADDR_TOP - PROCESS_STACK_SIZE)

struct process;

struct vma {
	unsigned long start;
	unsigned long end;
	int anon;
	int perm;
	int pma_handle;
	struct list_head list;
};

#define vma_size(vma)	\
	((vma)->end - (vma)->start)

struct vma *__request_vma(struct process *proc, unsigned long base,
		size_t size, unsigned int perm, int anon);

struct vma *request_vma(struct process *proc, int pma_handle,
		unsigned long base, size_t size,
		unsigned int perm, int anon);

void release_vma(struct process *proc, struct vma *vma);

void vspace_init(struct process *proc);

struct vma *find_vma(struct process *proc, unsigned long base);

int create_pma(int type, int right, int right_req,
		unsigned long base, size_t size);

#endif
