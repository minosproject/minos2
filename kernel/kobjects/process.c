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
#include <minos/handle.h>
#include <minos/procinfo.h>

#include "kobject_copy.h"

#define PROC_RIGHT	(KOBJ_RIGHT_READ | KOBJ_RIGHT_CTL)
#define PROC_RIGHT_MASK	(KOBJ_RIGHT_CTL)

static long process_send(struct kobject *kobj,
		void __user *data, size_t data_size,
		void __user *extra, size_t extra_size,
		uint32_t timeout)
{
	struct process *proc = (struct process *)kobj->data;
	struct poll_struct *ps = kobj->poll_struct;

	/*
	 * ROOT service will always poll to the process's
	 * request.
	 */
	ASSERT(proc == current_proc);

	spin_lock(&proc->request_lock);
	list_add_tail(&proc->request_list, &current->kobj.list);
	__event_task_wait(0, TASK_EVENT_ROOT_SERVICE, 0);
	spin_unlock(&proc->request_lock);

	poll_event_send(ps, EV_IN);

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
		errno = send_handle(current_proc, proc, fd, fd_right);

	wake_up(target, errno);
	proc->request_current = NULL;

	return 0;
}

static int process_page_fault_done(struct process *proc, int tid)
{
	struct task *task;

	if (tid < 0) {
		kill_process(proc);
		return 0;
	}

	task = get_task_by_tid(tid);
	if (!task)
		return -ENOENT;

	if (task->pid != proc->pid)
		return -EPERM;

	return wake_up(task, 0);
}

static long do_process_ctl(struct process *proc, int req, unsigned long data)
{
	unsigned long addr;

	switch (req) {
	case KOBJ_PROCESS_GET_PID:
		return proc->pid;
	case KOBJ_PROCESS_SETUP_SP:
		arch_set_task_user_stack(proc->head, data);
		return 0;
	case KOBJ_PROCESS_WAKEUP:
		return wake_up(proc->head, 0);
	case KOBJ_PROCESS_VA2PA:
		addr = translate_va_to_pa(&proc->vspace, data);
		if (addr == INVALID_ADDR)
			addr = -1;
		return addr;
	case KOBJ_PROCESS_PF_DONE:
		return process_page_fault_done(proc, (int)data);
	case KOBJ_PROCESS_EXIT:
		/*
		 * task will be sched out when in return to user.
		 * if the REQUEST_EXIT bit is seted in task->request
		 */
		process_die();
		return 0;
	case KOBJ_PROCESS_SETUP_REG0:
		arch_set_task_reg0(proc->head, data);
		return 0;
	case KOBJ_PROCESS_GRANT_RIGHT:
		data &= PROC_FLAGS_MASK;
		proc->flags |= data;
		return 0;
	default:
		break;
	}

	return -EPROTONOSUPPORT;
}

static long process_ctl(struct kobject *kobj, int req, unsigned long data)
{
	struct process *proc = (struct process *)kobj->data;

	switch (req) {
	case KOBJ_PROCESS_SETUP_SP:
	case KOBJ_PROCESS_WAKEUP:
	case KOBJ_PROCESS_PF_DONE:
	case KOBJ_PROCESS_SETUP_REG0:
	case KOBJ_PROCESS_GRANT_RIGHT:
		/*
		 * only root process can call these operations.
		 */
		if (!proc_is_root(current_proc))
			return -EPERM;
		break;
	case KOBJ_PROCESS_EXIT:
		if (current_proc != proc)
			return -EPERM;
		break;
	case KOBJ_PROCESS_VA2PA:
		if (!proc_can_vmctl(current_proc))
			return -EPERM;
		break;
	default:
		break;
	}

	return do_process_ctl(proc, req, data);
}

static void process_release(struct kobject *kobj)
{
	struct process *proc = (struct process *)kobj->data;
	struct task *task = proc->head, *tmp;

	for_all_task_in_process(proc, tmp) {
		if ((tmp->stat != TASK_STAT_STOPPED) || (tmp->cpu != -1))
			panic("wrong task state detect in %s\n", __func__);
	}

	while (task) {
		tmp = task->next;
		do_release_task(task);
		task = tmp;
	}

	/*
	 * close all the kobject which has not been closed
	 * by the task.
	 */
	release_proc_kobjects(proc);

	/*
	 * release the all resource of the process.
	 */
	vspace_deinit(proc);
	process_handles_deinit(proc);
	free(proc);
}

static struct kobject_ops proc_kobj_ops = {
	.send		= process_send,
	.recv		= process_recv,
	.reply		= process_reply,
	.release	= process_release,
	.ctl		= process_ctl,
};

static void process_kobject_init(struct process *proc)
{
	kobject_init(&proc->kobj, KOBJ_TYPE_PROCESS,
			PROC_RIGHT_MASK, (unsigned long)proc);
	proc->kobj.ops = &proc_kobj_ops;
}

struct process *create_root_process(task_func_t func, void *usp,
		int prio, int aff, unsigned long opt)
{
	struct process *proc;
	struct uproc_info *ui;

	/*
	 * the pid of the root service will fix to 0, kernel
	 * will only init the uproc_info of process 0.
	 */
	ui = get_uproc_info(0);
	ui->valid = 1;
	ui->pid = 0;
	strcpy(ui->cmd, "pangu.srv");

	proc = create_process(0, func, usp, prio, aff, opt);
	if (!proc)
		return NULL;

	proc->flags |= PROC_FLAGS_ROOT | PROC_FLAGS_VMCTL | PROC_FLAGS_HWCTL;
	proc->kobj.ops = &proc_kobj_ops;

	return proc;
}

static int process_create(struct kobject **kobjr, right_t *right, unsigned long data)
{
	struct process_create_arg args;
	struct process *proc;
	int ret;

	/*
	 * only root service can create process directly
	 */
	if (!proc_is_root(current_proc))
		return -EPERM;

	ret = copy_from_user(&args, (void *)data,
			sizeof(struct process_create_arg));
	if (ret <= 0)
		return -EFAULT;

	proc = create_process(args.pid, (task_func_t)args.entry,
			(void *)args.stack, args.aff,
			args.prio, args.flags);
	if (!proc)
		return -ENOMEM;

	process_kobject_init(proc);
	*kobjr = &proc->kobj;
	*right = PROC_RIGHT;

	return 0;
}
DEFINE_KOBJECT(process, KOBJ_TYPE_PROCESS, process_create);
