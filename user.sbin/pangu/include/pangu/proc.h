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

#define PROC_WAIT_NONE		0
#define PROC_WAIT_PID		1
#define PROC_WAIT_ANY		2

struct handle_desc {
	int handle;
	int right;
};

struct wait_entry {
	int pid;
	int type;
	long token;
	struct list_head list;
};

struct process {
	int proc_handle;		// used to control the process.
	int pid;
	int flags;

	struct list_head children;
	struct list_head clist;
	struct process *parent;

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

	struct list_head wait_head;

	/*
	 * link to the global user_proc_list if this process
	 * is a children of init process.
	 */
	struct list_head list;
};

#define proc_pid(proc) ((proc)->pid)
#define proc_flags(proc) ((proc)->flags)

typedef long (*syscall_hdl)(struct process *proc, struct proto *proto, void *data);

extern struct process *self;
extern struct process *rootfs_proc;
extern struct process *nvwa_proc;
extern struct process *chiyou_proc;

extern int fuxi_handle;
extern int nvwa_handle;
extern int chiyou_handle;
extern int proc_epfd;

struct epoll_event;
struct process_proto;

typedef long (*proc_event_handle_t)(struct process *proc,
		struct process_proto *proto, void *data, size_t size);

void self_init(int proc_handle, unsigned long vma_base, unsigned long vma_end);

void *map_self_memory(int pma_handle, size_t size, int perm);

int unmap_self_memory(void *base);

void wakeup_process(struct process *proc);

void handle_process_request(struct epoll_event *event, struct process *proc);

long pangu_procinfo(struct process *proc, struct proto *proto, void *data);
long pangu_taskstat(struct process *proc, struct proto *proto, void *data);
long pangu_proccnt(struct process *proc, struct proto *proto, void *data);

struct process *load_ramdisk_process(char *path,
		struct handle_desc *hdesc, int num_handle, int flags);

int register_request_entry(int handle, struct process *proc);
int unregister_request_entry(int handle, struct process *proc);

int alloc_pid(void);
void release_pid(int pid);

#endif
