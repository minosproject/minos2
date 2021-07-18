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

enum {
	KOBJ_PROCESS_GET_PID = 0x100,
	KOBJ_PROCESS_SETUP_SP,
	KOBJ_PROCESS_WAKEUP,
	KOBJ_PROCESS_VA2PA,
};

struct process_create_arg {
	unsigned long entry;
	unsigned long stack;
	int aff;
	int prio;
	unsigned long flags;
};

static ssize_t process_send(struct kobject *kobj,
		void __user *data, size_t data_size,
		void __user *extra, size_t extra_size,
		uint32_t timeout)
{
	return 0;
}

static ssize_t process_recv(struct kobject *kobj,
		void __user *data, size_t data_size,
		void __user *extra, size_t extra_size,
		uint32_t timeout)
{
	return 0;
}

static void process_release(struct kobject *kobj)
{

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
	default:
		pr_err("%s unsupport ctl reqeust %d\n", __func__, req);
		break;
	}

	return -EPROTONOSUPPORT;
}

static struct kobject_ops proc_kobj_ops = {
	.send		= process_send,
	.recv		= process_recv,
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
			(void *)args.stack, args.aff, args.prio, args.flags);
	if (!proc)
		return ERROR_PTR(ENOMEM);

	process_kobject_init(proc, right);

	return &proc->kobj;
}
DEFINE_KOBJECT(process, KOBJ_TYPE_PROCESS, process_create);
