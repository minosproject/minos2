#ifndef __MINOS_PROC_H__
#define __MINOS_PROC_H__

#include <minos/current.h>
#include <uspace/vspace.h>
#include <uspace/kobject.h>
#include <uspace/handle.h>
#include <uspace/iqueue.h>

#define PROCESS_NAME_SIZE	32

struct task;

#define PROC_FLAGS_VMCTL	(1 << 0)
#define PROC_FLAGS_HWCTL	(1 << 1)
#define PROC_FLAGS_ROOT		(1 << 31)
#define PROC_FLAGS_MASK		(PROC_FLAGS_VMCTL | PROC_FLAGS_HWCTL)

struct process {
	int pid;
	int flags;
	int task_cnt;
	int stopped;

	struct vspace vspace;

	/*
	 * handle_desc_table will store all the kobjects created
	 * and kobjects connected by this process. and
	 *
	 * when close or open kobject, it will only clear or
	 * set the right for related kobject in kobj_table.
	 */
	struct handle_desc *handle_desc_table;
	struct task *root_task;
	struct list_head task_list;
	spinlock_t lock;

	struct kobject kobj;
	struct iqueue iqueue;
};

#define current_proc		(struct process *)current->vs->pdata
#define task_to_proc(task)	(struct process *)((task)->vs->pdata)

static inline int proc_is_root(struct process *proc)
{
	return !!(proc->flags & PROC_FLAGS_ROOT);
}

static inline int proc_can_vmctl(struct process *proc)
{
	return !!(proc->flags & PROC_FLAGS_VMCTL);
}

static inline int proc_can_hwctl(struct process *proc)
{
	return !!(proc->flags & PROC_FLAGS_HWCTL);
}

struct process *create_process(int pid, task_func_t func,
		void *usp, int prio, int aff, unsigned long opt);

void process_die(void);

void kill_process(struct process *proc, int handle);

void clean_process_on_pcpu(struct pcpu *pcpu);

int process_page_fault(struct process *proc, uint64_t virtaddr, uint64_t info);

int wake_up_process(struct process *proc);

#endif
