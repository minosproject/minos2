#ifndef __MINOS_PROC_H__
#define __MINOS_PROC_H__

#include <minos/vspace.h>
#include <minos/kobject.h>
#include <minos/handle.h>
#include <minos/iqueue.h>

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
	struct task *head;
	struct task *tail;
	spinlock_t lock;

	struct kobject kobj;
	struct iqueue iqueue;
	void *pdata;
};

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

#define for_all_task_in_process(proc, task)	\
	for (task = proc->head; task != NULL; task = task->next)

struct process *create_process(int pid, task_func_t func,
		void *usp, int prio, int aff, unsigned long opt);

struct task *create_task_for_process(struct process *proc,
		unsigned long func, void *usp, int prio,
		int aff, unsigned long flags);

void process_die(void);

void kill_process(struct process *proc, int handle);

void clean_process_on_pcpu(struct pcpu *pcpu);

int process_page_fault(struct process *proc, uint64_t virtaddr, uint64_t info);

#endif
