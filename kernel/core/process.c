/*
 * Copyright (C) 2020 Min Le (lemin9538@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <minos/minos.h>
#include <minos/sched.h>
#include <minos/mm.h>
#include <minos/atomic.h>
#include <minos/task.h>
#include <minos/proc.h>
#include <minos/kobject.h>

#ifndef CONFIG_NR_PROC
#define CONFIG_NR_PROC 512
#endif

#define OS_NR_PROC CONFIG_NR_PROC

#define KOBJ_RIGHT_PROCESS KOBJ_RIGHT_NONE

static DEFINE_SPIN_LOCK(pid_lock);
static DECLARE_BITMAP(pid_map, CONFIG_NR_PROC);
static struct process *os_processes[CONFIG_NR_PROC];

struct process *get_process_by_pid(int pid)
{
	if (pid >= CONFIG_NR_PROC)
		return NULL;

	return os_processes[pid];
}

static int alloc_pid(void)
{
	int pid = -1;

	/*
	 * check whether this task is a global task or
	 * a task need to attach to the special pcpu and
	 * also check the whether the prio is valid or
	 * invalid. by the side the idle and stat task is
	 * created by the pcpu itself at the boot stage
	 */
	spin_lock(&pid_lock);
	pid = find_next_zero_bit(pid_map, OS_NR_PROC, 0);
		if (pid >= OS_NR_TASKS)
			pid = -1;
		else
			set_bit(pid, pid_map);
	spin_unlock(&pid_lock);

	return pid;
}

static void release_pid(int pid)
{
	if (pid > OS_NR_PROC)
		return;

	os_processes[pid] = NULL;
	clear_bit(pid, pid_map);
}

static void add_task_to_process(struct process *proc, struct task *task)
{
	unsigned long flags;

	spin_lock_irqsave(&proc->lock, flags);
	task->next = proc->head;
	proc->tail = task;
	proc->task_cnt++;

	/*
	 * also link the task's object to the proce's child
	 * list.
	 */
	list_add_tail(&proc->kobj.child, &task->kobj.parent);

	spin_unlock_irqrestore(&proc->lock, flags);
}

struct task *create_task_for_process(struct process *proc, char *name,
		unsigned long func, void *user_sp, int prio,
		int aff, unsigned long flags)
{
	struct task *task;

	task = create_task(name, (task_func_t)func, user_sp,
			prio, aff, flags, proc);
	if (!task)
		return NULL;

	task->pid = proc->pid;
	add_task_to_process(proc, task);

	return task;
}

struct process *create_process(char *name, task_func_t func,
		void *usp, int prio, int aff, unsigned long opt)
{
	struct process *proc = NULL;
	int pid = alloc_pid();
	struct task *task;
	int ret;

	if (pid < 0)
		return NULL;

	proc = zalloc(sizeof(struct process));
	if (!proc)
		goto proc_alloc_fail;

	ret = init_proc_handles(proc);
	if (ret)
		goto handle_init_fail;

	ret = vspace_init(&proc->vspace);
	if (ret)
		goto vspace_init_fail;
	proc->pid = pid;

	/*
	 * create a root task for this process
	 */
	task = create_task(name, func, usp, prio, aff, opt |
			TASK_FLAGS_NO_AUTO_START | TASK_FLAGS_ROOT, proc);
	if (!task)
		goto task_create_fail;

	/*
	 * if the process is not root service, then its right
	 * will be given by root service, when create the process.
	 */
	kobject_init(&proc->kobj, proc->pid, KOBJ_TYPE_PROCESS,
			KOBJ_FLAGS_INVISABLE, KOBJ_RIGHT_NONE,
			(unsigned long)proc);

	kobject_init(&task->kobj, pid, KOBJ_TYPE_THREAD,
			KOBJ_FLAGS_INVISABLE, 0, (unsigned long)task);
	task->kobj.name = task->name;

	proc->head = task;
	proc->tail = task;
	proc->task_cnt = 1;
	task->pid = proc->pid;

	/*
	 * add the thread to the process's kobject list.
	 */
	strncpy(proc->name, name, PROCESS_NAME_SIZE - 1);
	list_add_tail(&proc->kobj.child, &task->kobj.parent);

	return proc;

task_create_fail:
	vspace_deinit(&proc->vspace);
vspace_init_fail:
	deinit_proc_handles(proc);
handle_init_fail:
	free(proc);
proc_alloc_fail:
	release_pid(pid);

	return NULL;
}
