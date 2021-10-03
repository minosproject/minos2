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

void release_pid(int pid)
{
	ASSERT(!(pid > OS_NR_PROC));
	clear_bit(pid, pid_map);
}

static int pid_subsys_init(void)
{
	set_bit(0, pid_map);
	return 0;
}
subsys_initcall(pid_subsys_init);

static int add_task_to_process(struct process *proc, struct task *task)
{
	int ret = 0;

	spin_lock(&proc->lock);
	if (proc->stopped) {
		ret = 1;
		goto out;
	}

	task->next = proc->head;
	proc->tail = task;
	proc->task_cnt++;
	kobject_get(&proc->kobj);

out:
	spin_unlock(&proc->lock);
	return ret;
}

struct task *create_task_for_process(struct process *proc,
		unsigned long func, void *user_sp, int prio,
		int aff, unsigned long flags)
{
	struct task *task;

	if (proc->stopped)
		return NULL;

	task = create_task(NULL, (task_func_t)func, user_sp,
			prio, aff, flags, proc);
	if (!task)
		return NULL;

	task->pid = proc->pid;
	if (add_task_to_process(proc, task)) {
		do_release_task(task);
		return NULL;
	}

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

	proc->pid = pid;
	ret = init_proc_handles(proc);
	if (ret)
		goto handle_init_fail;

	ret = vspace_init(proc);
	if (ret)
		goto vspace_init_fail;

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
	kobject_init(&task->kobj, KOBJ_TYPE_THREAD,
			KOBJ_RIGHT_CTL, (unsigned long)task);
	kobject_init(&proc->kobj, KOBJ_TYPE_PROCESS,
			KOBJ_RIGHT_RW | KOBJ_RIGHT_CTL,
			(unsigned long)proc);

	proc->head = task;
	proc->tail = task;
	proc->task_cnt = 1;
	task->pid = proc->pid;
	spin_lock_init(&proc->request_lock);
	init_list(&proc->request_list);

	return proc;

task_create_fail:
	vspace_deinit(proc);
vspace_init_fail:
	process_handles_deinit(proc);
handle_init_fail:
	free(proc);
proc_alloc_fail:
	release_pid(pid);

	return NULL;
}

static void task_exit_helper(void *data)
{

}

static void request_process_stop(struct process *proc)
{
	struct task *tmp;
	int old;

	/*
	 * someone called exit() aready.
	 */
	old = cmpxchg(&proc->stopped, 0, 1);
	if (old != 0)
		return;

	for_all_task_in_process(proc, tmp) {
		/*
		 * other task can not get the instance of this
		 * task, but the task who already get the instance
		 * of this task can sending data to it currently.
		 */
		clear_task_by_tid(tmp->tid);
		tmp->request |= TASK_REQ_STOP;
		if (tmp == current)
			continue;

		/*
		 * make all the running taskes enter into kernel, so
		 * when return to user, it can detected the task need
		 * to exit.
		 *
		 * if the task is waitting for the root service, do not
		 * wakeup it, since the root service will finnally wake
		 * up this task.
		 */
		if (tmp->ti.flags & __TIF_IN_USER)
			smp_function_call(tmp->cpu, task_exit_helper, NULL, 0);
		else if ((tmp->stat == TASK_STAT_WAIT_EVENT) &&
				(tmp->wait_type == TASK_EVENT_ROOT_SERVICE))
			wake_up(tmp, -EABORT);
	}
}

void process_die(void)
{
	gp_regs *regs = current_regs;

	if (is_root_process(current_proc)) {
		pr_fatal("root service exit 0x%x %d\n", regs->pc, regs->x0);
		panic("root service hang, system crash");
	}

	request_process_stop(current_proc);
}

void kill_process(struct process *proc)
{
	request_process_stop(proc);
}
