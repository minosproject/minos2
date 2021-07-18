#ifndef __MINOS_PROC_H__
#define __MINOS_PROC_H__

#include <minos/vspace.h>
#include <minos/kobject.h>
#include <minos/handle.h>

#define PROCESS_NAME_SIZE	32

struct task;
struct service;

struct process {
	int pid;
	int task_cnt;
	void *pdata;

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

	char name[PROCESS_NAME_SIZE];
};

#define for_all_task_in_process(proc, task)	\
	for (task = proc->head; task != NULL; task = task->next)

struct process *create_process(char *name, task_func_t func,
		void *usp, int prio, int aff, unsigned long opt);

struct task *create_task_for_process(struct process *proc, char *name,
		unsigned long func, void *usp, int prio,
		int aff, unsigned long flags);

struct process *get_process_by_pid(int pid);

#endif
