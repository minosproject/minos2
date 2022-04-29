/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
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
#include <minos/kobject.h>
#include <minos/uaccess.h>
#include <minos/mm.h>
#include <minos/vspace.h>
#include <minos/proc.h>
#include <minos/task.h>
#include <minos/sched.h>

void sys_exit(int errno)
{
	if (current->flags & TASK_FLAGS_ROOT)
		process_die();
	else
		task_die();
}

void sys_exitgroup(int errno)
{
	process_die();
}

void release_thread(struct task *task)
{
	struct process *proc = task->proc;
	unsigned long flags;
	int tflags = task->flags;

	spin_lock_irqsave(&proc->lock, flags);
	list_del(&task->proc_list);
	proc->task_cnt--;
	spin_unlock_irqrestore(&proc->lock, flags);

	do_release_task(task);

	if (tflags & TASK_FLAGS_ROOT)
		__release_handle(task->proc, 0);
	/*
	 * the root task is put the refcnt of the handle 0.
	 */
	kobject_put(&proc->kobj);
}

static int add_task_to_process(struct process *proc, struct task *task)
{
	int ret = 0;

	spin_lock(&proc->lock);
	if (proc->stopped) {
		ret = 1;
		goto out;
	}

	list_add_tail(&proc->task_list, &task->proc_list);
	proc->task_cnt++;
	kobject_get(&proc->kobj);
out:
	spin_unlock(&proc->lock);
	return ret;
}

int sys_clone(int flags, void *stack, int *ptid, void *tls, int *ctid)
{
	struct process *proc = current_proc;
	gp_regs *regs = current_user_regs;
	struct task *task;
	int ret;

	if (proc->stopped)
		return -EPERM;

	task = create_task(NULL, (task_func_t)regs->pc,
			TASK_STACK_SIZE, stack, -1, -1,
			flags | TASK_FLAGS_NO_AUTO_START, proc);
	if (!task)
		return -ENOSPC;

	ret = copy_to_user(ptid, &task->tid, sizeof(int));
	if (ret <= 0) {
		do_release_task(task);
		return ret;
	}

	ret = add_task_to_process(proc, task);
	if (ret) {
		do_release_task(task);
		return ret;
	}

	task->pid = proc->pid;
	arch_set_tls(task, (unsigned long)tls);
	task_ready(task, 0);

	return task->tid;
}
