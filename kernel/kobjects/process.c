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
#include <minos/sched.h>
#include <minos/poll.h>
#include <minos/task.h>

#include "kobject_copy.h"

enum {
	KOBJ_PROCESS_GET_PID = 0x100,
	KOBJ_PROCESS_SETUP_SP,
	KOBJ_PROCESS_WAKEUP,
	KOBJ_PROCESS_VA2PA,
	KOBJ_PROCESS_EXIT,
};

struct process_create_arg {
	unsigned long entry;
	unsigned long stack;
	int aff;
	int prio;
	unsigned long flags;
};

static long process_send(struct kobject *kobj,
		void __user *data, size_t data_size,
		void __user *extra, size_t extra_size,
		uint32_t timeout)
{
	struct process *proc = (struct process *)kobj->data;
	struct poll_struct *ps = &kobj->poll_struct;

	/*
	 * ROOT service will always poll to the process's
	 * request.
	 */
	ASSERT(proc != current_proc);

	spin_lock(&proc->request_lock);
	list_add_tail(&proc->request_list, &current->kobj.list);
	__event_task_wait(0, TASK_EVENT_ROOT_SERVICE, 0);
	spin_unlock(&proc->request_lock);

	poll_event_send(ps, POLLIN, POLLIN_WRITE);

	return wait_event();
}

static long process_recv(struct kobject *kobj, void __user *data,
		size_t data_size, size_t *actual_data, void __user *extra,
		size_t extra_size, size_t *actual_extra, uint32_t timeout)
{
	struct process *proc = (struct process *)kobj->data;
	struct kobject *thread = NULL;
	struct task *task;
	int ret = 0;

	spin_lock(&proc->request_lock);
	if (is_list_empty(&proc->request_list)) {
		ret = -EAGAIN;
		goto out;
	}

	thread = list_first_entry(&proc->request_list,
			struct kobject, list);
	list_del(&thread->list);
out:
	spin_unlock(&proc->request_lock);

	if (!thread)
		return ret;

	task = (struct task *)thread->data;
	ret = kobject_copy_ipc_payload(current, task,
			actual_data, actual_extra, 1, 0);
	if (ret < 0)
		return -EAGAIN;

	proc->request_current = task;

	return 0;
}

static int process_reply(struct kobject *kobj, right_t right, long token,
		long errno, handle_t fd, right_t fd_right)
{
	struct process *proc = (struct process *)kobj->data;
	struct task *target = proc->request_current;

	if (target == NULL)
		return -ENOENT;

	if (fd > 0)
		errno = kobject_send_handle(proc, target->proc, fd, fd_right);

	wake_up(proc->request_current, errno);
	proc->request_current = NULL;

	return 0;
}

static void wait_all_task_stop(struct process *proc)
{
	struct task *task;
	int done;

	/*
	 * any better ways to know whether this thread has been
	 * operate by other thread ?, the case will happed in
	 * process IPC, such as endpoint, irq etc.
	 */
	for (;;) {
		done = 0;
		for_all_task_in_process(proc, task) {
			if (task == current)
				continue;
			done |= (task->stat != TASK_STAT_STOPPED);
		}

		if (!done)
			break;

		sched();
	}
}

static void process_release(struct kobject *kobj)
{
	struct process *proc = (struct process *)kobj->data;

	/*
	 * wait again, the calling task need to ensure is
	 * alreay exited.
	 */
	wait_all_task_stop(proc);

	/*
	 * now can release the all process's resource now.
	 * the important things is to close all the kobject
	 * this thread has been opened. TBD
	 */
}

static int send_process_exit_event(struct process *proc)
{
	struct poll_struct *ps = &proc->kobj.poll_struct;

	return poll_event_send(ps, POLLIN, POLLIN_EXIT);
}

static void task_exit_helper(void *data)
{

}

static int process_exit(struct process *proc)
{
	struct task *task = current;
	struct task *tmp;

	ASSERT(task->pid != proc->pid);
	proc->exit = 1;

	for_all_task_in_process(proc, tmp) {
		/*
		 * other task can not get the instance of this
		 * task, but the task who already get the instance
		 * of this task can sending data to it currently.
		 */
		clear_task_by_tid(task->tid);

		task->request |= TASK_REQ_EXIT;
		if (tmp == task)
			continue;

		/*
		 * make all the running taskes enter into kernel, so
		 * when return to user, it can detected the task need
		 * to exit.
		 */
		if (tmp->ti.flags & __TIF_IN_USER)
			smp_function_call(tmp->cpu, task_exit_helper, NULL, 0);
		else if ((task->stat == TASK_STAT_WAIT_EVENT) &&
				(task->wait_type != TASK_EVENT_ROOT_SERVICE))
			wake_up(tmp, -EABORT);
	}

	/*
	 * wait all task in this process going to stop stat
	 */
	wait_all_task_stop(proc);

	/*
	 * send a kernel event to the root service to indicate that
	 * this process will exit() soon, before sending the message
	 * to the root service, mask this task do_not_preempt(). since
	 * this task will stopped soon.
	 */
	do_not_preempt();

	return send_process_exit_event(proc);
}

static long process_ctl(struct kobject *kobj, int req, unsigned long data)
{
	struct process *proc = (struct process *)kobj->data;
	unsigned long addr;

	switch (req) {
	case KOBJ_PROCESS_GET_PID:
		return proc->pid;
	case KOBJ_PROCESS_SETUP_SP:
		if (current_proc == proc)
			return -EPERM;
		arch_set_task_user_stack(proc->head, data);
		return 0;
	case KOBJ_PROCESS_WAKEUP:
		wake_up(proc->head, 0);
		break;
	case KOBJ_PROCESS_VA2PA:
		if (!(kobj->right & KOBJ_RIGHT_HEAP_SELFCTL))
			return -1;

		addr = translate_va_to_pa(&proc->vspace, data);
		if (addr == INVALID_ADDR)
			addr = -1;
		return addr;
	case KOBJ_PROCESS_EXIT:
		/*
		 * task will be sched out when in return to user.
		 * if the REQUEST_EXIT bit is seted in task->request
		 */
		if (process_exit(proc)) {
			pr_err("process-%d %s exit fail\n",
					proc->pid, proc->name);
			return -EABORT;
		} else {
			return 0;
		}
		break;
	default:
		pr_err("%s unsupport ctl reqeust %d\n", __func__, req);
		break;
	}

	return -EPROTONOSUPPORT;
}

static struct kobject_ops proc_kobj_ops = {
	.send		= process_send,
	.recv		= process_recv,
	.reply		= process_reply,
	.release	= process_release,
	.ctl		= process_ctl,
};

static void process_kobject_init(struct process *proc, right_t right)
{
	kobject_init(&proc->kobj, current_pid, KOBJ_TYPE_PROCESS,
			KOBJ_FLAGS_INVISABLE, right, (unsigned long)proc);
	proc->kobj.name = proc->name;
	proc->kobj.ops = &proc_kobj_ops;
	register_namespace(proc);
}

struct process *create_root_process(char *name, task_func_t func,
		void *usp, int prio, int aff, unsigned long opt)
{
	struct process *proc;

	proc = create_process(name, func, usp, prio, aff, opt);
	if (!proc)
		return NULL;

	proc->kobj.right = KOBJ_RIGHT_ROOT;
	proc->kobj.name = proc->name;
	proc->kobj.ops = &proc_kobj_ops;
	register_namespace(proc);

	return proc;
}

static struct kobject *process_create(char *str, right_t right,
		right_t right_req, unsigned long data)
{
	struct kobject *kobj = &current_proc->kobj;
	struct process_create_arg args;
	struct process *proc;
	int ret;

	/*
	 * only root service can create process directly
	 */
	if (kobj->right != KOBJ_RIGHT_ROOT)
		return ERROR_PTR(EPERM);

	ret = copy_from_user(&args, (void *)data,
			sizeof(struct process_create_arg));
	if (ret <= 0)
		return NULL;

	proc = create_process(str, (task_func_t)args.entry,
			(void *)args.stack, args.aff,
			args.prio, args.flags);
	if (!proc)
		return ERROR_PTR(ENOMEM);

	process_kobject_init(proc, right);

	return &proc->kobj;
}
DEFINE_KOBJECT(process, KOBJ_TYPE_PROCESS, process_create);
