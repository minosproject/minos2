#ifndef __PANGU_PROC_H__
#define __PANGU_PROC_H__

#include <minos/list.h>
#include <minos/types.h>

#include <pangu/vma.h>
#include <pangu/resource.h>

#define TASK_FLAGS_SRV			BIT(0)
#define TASK_FLAGS_DRV			BIT(1)
#define TASK_FLAGS_VCPU			BIT(2)
#define TASK_FLAGS_REALTIME		BIT(3)
#define TASK_FLAGS_KERNEL_MASK		(0xff)

#define TASK_FLAGS_DEDICATED_HEAP	BIT(16)

#define MAX_ARGC	(PAGE_SIZE / sizeof(char *))

struct process {
	int pid;
	int flags;
	handle_t proc_handle;		// used to control the process.

	struct vma *elf_vma;
	struct vma *stack_vma;
	struct list_head vma_free;
	struct list_head vma_used;

	union {
		struct resource *resource;
		void *pdata;
	};

	struct list_head list;		// link to all the process in the system.

};

extern struct process *self;

void self_init(unsigned long vma_base, unsigned long vma_end);

void *map_self_memory(handle_t pma_handle, size_t size, int perm);

int unmap_self_memory(void *base);

void wakeup_all_process(void);

int load_ramdisk_process(char *path, int argc, char **argv,
		unsigned long flags, void *pdata);
#endif
