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

struct process *create_process(int pid, task_func_t func,
		void *usp, int prio, int aff, unsigned long opt)
{
	struct uproc_info *ui = get_uproc_info(pid);
	struct process *proc = NULL;
	struct task *task;
	int ret;

	proc = zalloc(sizeof(struct process));
	if (!proc)
		return NULL;

	/*
	 * if the process is not root service, then its right
	 * will be given by root service, when create the process.
	 */
	proc->pid = pid;
	init_list(&proc->task_list);
	spin_lock_init(&proc->lock);

	ret = vspace_init(proc);
	if (ret)
		goto vspace_init_fail;

	/*
	 * create a root task for this process
	 */
	task = create_task(ui->cmd, func, usp, prio, aff, opt |
			TASK_FLAGS_NO_AUTO_START | TASK_FLAGS_ROOT, proc, NULL);
	if (!task)
		goto task_create_fail;

	proc->root_task = task;
	list_add_tail(&proc->task_list, &task->proc_list);
	task->pid = proc->pid;
	proc->task_cnt++;

	ret = init_proc_handles(proc);
	if (ret)
		goto handle_init_fail;

	return proc;

handle_init_fail:
	do_release_task(task);
task_create_fail:
	vspace_deinit(proc);
vspace_init_fail:
	free(proc);

	return NULL;
}

static void task_exit_helper(void *data)
{

}

static void request_process_stop(struct process *proc, int handle)
{
	struct task *tmp;
	int old;

	ASSERT(handle >= 0);

	/*
	 * someone called exit() aready.
	 */
	old = cmpxchg(&proc->stopped, 0, 1);
	if (old != 0)
		return;

	spin_lock(&proc->lock);
	list_for_each_entry(tmp, &proc->task_list, proc_list) {
		/*
		 * other task can not get the instance of this
		 * task, but the task who already get the instance
		 * of this task can sending data to it currently.
		 */
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
	spin_unlock(&proc->lock);

	if (handle == 0) {
		/*
		 * the handle is 0 means this stop request is triggered by
		 * the process self.
		 */
		poll_event_send_with_data(proc->kobj.poll_struct, EV_KERNEL,
			POLL_KEV_PROCESS_EXIT, 0, 0, 0);
	}
}

/*
 * the process call exit() itself.
 */
void process_die(void)
{
	gp_regs *regs = current_regs;

	if (proc_is_root(current_proc)) {
		pr_fatal("root service exit 0x%x %d\n", regs->pc, regs->x0);
		panic("root service hang, system crash\n");
	}

	request_process_stop(current_proc, 0);
}

/*
 * killed by root service.
 */
void kill_process(struct process *proc, int handle)
{
	request_process_stop(proc, handle);
}

int process_page_fault(struct process *proc, uint64_t virtaddr, uint64_t info)
{
	struct iqueue *iqueue = &proc->iqueue;
	struct task *task = current;
	uint32_t token = new_event_token();
	long ret;

	spin_lock(&iqueue->lock);
	list_add_tail(&iqueue->processing_list, &task->list);
	__event_task_wait(token, TASK_EVENT_ROOT_SERVICE, 0);
	spin_unlock(&iqueue->lock);

	/*
	 * send the page fault event to the root service. need
	 * to consider when event is send failed. TBD
	 */
	poll_event_send_with_data(proc->kobj.poll_struct,
			EV_KERNEL, POLL_KEV_PAGE_FAULT,
			virtaddr, info, token);

	/*
	 * handle page_fault fail, then the ret is the handle
	 * of this process in root service.
	 */
	wait_event(&ret);

	return ret;
}

static long process_recv(struct kobject *kobj, void __user *data,
		size_t data_size, size_t *actual_data, void __user *extra,
		size_t extra_size, size_t *actual_extra, uint32_t timeout)
{
	struct process *proc = (struct process *)kobj->data;

	if (!proc_is_root(current_proc)) {
		pr_err("only root service can read process request\n");
		return -EPERM;
	}

	return iqueue_recv(&proc->iqueue, data, data_size, actual_data,
			extra, extra_size, actual_extra, timeout);
}

static int process_reply(struct kobject *kobj, right_t right, long token,
		long errno, handle_t fd, right_t fd_right)
{
	struct process *proc = (struct process *)kobj->data;

	return iqueue_reply(&proc->iqueue, right, token, errno, fd, fd_right);
}

static long do_process_ctl(struct process *proc, int req, unsigned long data)
{
	switch (req) {
	case KOBJ_PROCESS_GET_PID:
		return proc->pid;
	case KOBJ_PROCESS_SETUP_SP:
		arch_set_task_user_stack(proc->root_task, data);
		return 0;
	case KOBJ_PROCESS_WAKEUP:
		return wake_up(proc->root_task, 0);
	case KOBJ_PROCESS_KILL:
		kill_process(proc, (int)data);
		return 0;
	case KOBJ_PROCESS_SETUP_REG0:
		arch_set_task_reg0(proc->root_task, data);
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

	if (!proc_is_root(current_proc))
		return -EPERM;

	return do_process_ctl(proc, req, data);
}

int do_process_release(struct kobject *kobj)
{
	struct process *proc = (struct process *)kobj->data;

	if (!is_list_empty(&proc->task_list)) {
		pr_err("some task still running\n");
		return -EBUSY;
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

	return 0;
}

static void process_release(struct kobject *kobj)
{
	struct pcpu *pcpu = __get_pcpu();

	/*
	 * here all the task of this process has been cloesd, now
	 * the process can be safe released, for better perference
	 * put it the local pcpu's process's list.
	 */
	list_add_tail(&pcpu->die_process, &kobj->list);
	__put_pcpu(pcpu);
}

void clean_process_on_pcpu(struct pcpu *pcpu)
{
	struct kobject *kobj;
	unsigned long flags;

	for (;;) {
		kobj = NULL;
		local_irq_save(flags);
		if (!is_list_empty(&pcpu->die_process)) {
			kobj = list_first_entry(&pcpu->die_process,
					struct kobject, list);
			list_del(&kobj->list);
		}
		local_irq_restore(flags);

		if (!kobj)
			break;

		/*
		 * the process can not be clean up now, re-add it to the
		 * die_process list, waitting for next time.
		 */
		if (do_process_release(kobj)) {
			local_irq_save(flags);
			list_add(&pcpu->die_process, &kobj->list);
			local_irq_restore(flags);
		}
	}
}

static long process_send(struct kobject *kobj,
		void __user *data, size_t data_size,
		void __user *extra, size_t extra_size,
		uint32_t timeout)
{
	struct process *proc = (struct process *)kobj->data;

	/*
	 * ROOT service will always poll to the process's
	 * request.
	 */
	ASSERT(!proc_is_root(current_proc));

	return iqueue_send(&proc->iqueue, data,
			data_size, extra, extra_size, timeout);
}

static int process_close(struct kobject *kobj, right_t right, struct process *proc)
{
	return 0;
}

static struct kobject_ops proc_kobj_ops = {
	.recv		= process_recv,
	.send		= process_send,
	.reply		= process_reply,
	.release	= process_release,
	.ctl		= process_ctl,
	.close		= process_close,
};

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

	iqueue_init(&proc->iqueue, 0, &proc->kobj);
	kobject_init(&proc->kobj, KOBJ_TYPE_PROCESS,
			PROC_RIGHT_MASK, (unsigned long)proc);
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

	iqueue_init(&proc->iqueue, 0, &proc->kobj);
	kobject_init(&proc->kobj, KOBJ_TYPE_PROCESS,
			PROC_RIGHT_MASK, (unsigned long)proc);
	proc->kobj.ops = &proc_kobj_ops;
	*kobjr = &proc->kobj;
	*right = PROC_RIGHT;

	return 0;
}
DEFINE_KOBJECT(process, KOBJ_TYPE_PROCESS, process_create);
