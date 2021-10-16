#ifndef __MINOS_PROC_H__
#define __MINOS_PROC_H__

#include <minos/vspace.h>
#include <minos/kobject.h>
#include <minos/handle.h>

#define PROCESS_NAME_SIZE	32

struct task;

#define PROC_FLAGS_VMCTL	(1 << 0)
#define PROC_FLAGS_HWCTL	(1 << 1)
#define PROC_FLAGS_ROOT		(1 << 31)
#define PROC_FLAGS_MASK		(PROC_FLAGS_VMCTL | PROC_FLAGS_HWCTL)

struct process {
	int pid;
	int task_cnt;
	int flags;
	void *pdata;

	int stopped;

	struct task *head;
	struct task *tail;
	struct kobject kobj;
	spinlock_t lock;

	struct vspace vspace;

	/*
	 * handle_desc_table will store all the kobjects created
	 * and kobjects connected by this process. and
	 *
	 * when close or open kobject, it will only clear or
	 * set the right for related kobject in kobj_table.
	 */
	struct handle_desc *handle_desc_table;
	spinlock_t kobj_lock;

	struct list_head request_list;
	spinlock_t request_lock;
	struct task *request_current;
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

struct process *create_process(char *name, task_func_t func,
		void *usp, int prio, int aff, unsigned long opt);

struct task *create_task_for_process(struct process *proc,
		unsigned long func, void *usp, int prio,
		int aff, unsigned long flags);

void process_die(void);

void kill_process(struct process *proc);

void release_pid(int pid);

#endif
