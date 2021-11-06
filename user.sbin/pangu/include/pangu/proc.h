#ifndef __PANGU_PROC_H__
#define __PANGU_PROC_H__

#include <minos/list.h>
#include <minos/types.h>
#include <minos/procinfo.h>

#include <pangu/mm.h>

#define TASK_FLAGS_SRV			BIT(0)
#define TASK_FLAGS_DRV			BIT(1)
#define TASK_FLAGS_VCPU			BIT(2)
#define TASK_FLAGS_REALTIME		BIT(3)
#define TASK_FLAGS_KERNEL_MASK		(0xff)

#define MAX_ARGC	(PAGE_SIZE / sizeof(char *))

#define PROCESS_NAME_SIZE 64

#define PROC_FLAGS_VMCTL	(1 << 0)
#define PROC_FLAGS_HWCTL	(1 << 1)

struct request_entry;
struct uproc_info;

struct handle_desc {
	int handle;
	int right;
};

struct process {
	int proc_handle;		// used to control the process.

	struct vma elf_vma;
	struct vma init_stack_vma;
	struct vma anon_stack_vma;

	/*
	 * mmap used for mmap.
	 */
	struct list_head vma_free;
	struct list_head vma_used;

	/*
	 * heap area.
	 */
	unsigned long brk_end;
	unsigned long brk_start;
	unsigned long brk_cur;

	struct list_head list;		// link to all the process in the system.
	struct uproc_info *pinfo;
};

typedef long (*syscall_hdl)(struct process *proc, struct proto *proto, void *data);

extern struct process *self;
extern struct process *rootfs_proc;
extern struct process *nvwa_proc;
extern struct process *chiyou_proc;

extern int fuxi_handle;
extern int nvwa_handle;
extern int chiyou_handle;
extern int proc_epfd;

extern struct list_head process_list;

struct epoll_event;
struct process_proto;

typedef long (*proc_event_handle_t)(struct process *proc,
		struct process_proto *proto, void *data, size_t size);

void self_init(unsigned long vma_base, unsigned long vma_end);

void *map_self_memory(int pma_handle, size_t size, int perm);

int unmap_self_memory(void *base);

void wakeup_process(struct process *proc);

void handle_process_request(struct epoll_event *event, struct process *proc);

long process_procinfo_handler(struct process *proc,
		struct proto *proto, void *data);
long process_taskstat_handler(struct process *proc,
		struct proto *proto, void *data);
long process_proccnt_handler(struct process *proc,
		struct proto *proto, void *data);

struct process *load_ramdisk_process(char *path,
		struct handle_desc *hdesc, int num_handle, int flags);

int register_request_entry(int handle, struct process *proc);
int unregister_request_entry(int handle, struct process *proc);

struct uproc_info *alloc_procinfo(char *path, int flags);
void release_procinfo(struct uproc_info *pinfo);

#endif
