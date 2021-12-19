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

static long thread_send(struct kobject *kobj,
		void __user *data, size_t data_size,
		void __user *extra, size_t extra_size,
		uint32_t timeout)
{
	struct task *task = (struct task *)kobj->data;

	/*
	 * ROOT service will always poll to the process's
	 * request.
	 */
	ASSERT(!proc_is_root(current_proc));
	ASSERT(task->proc != NULL);

	return iqueue_send(&task->proc->iqueue, data,
			data_size, extra, extra_size, timeout);
}

static void thread_release(struct kobject *kobj)
{
	/*
	 * do nothing here, the task will released by the process
	 * when all the task is exited.
	 */
}

static long thread_ctl(struct kobject *kobj, int req, unsigned long data)
{
	struct task *task = (struct task *)kobj->data;

	ASSERT(task == current);

	return -EPROTONOSUPPORT;
}

static int thread_close(struct kobject *kobj,
		right_t right, struct process *proc)
{
	/*
	 * task is closed by kernel, do nothing here, this means
	 * the process has been requested to stop.
	 */
	if (proc == current_proc)
		process_die();

	return 0;
}

struct kobject_ops thread_kobj_ops = {
	.send		= thread_send,
	.release	= thread_release,
	.ctl		= thread_ctl,
	.close		= thread_close
};

static int thread_create(struct kobject **kobj, right_t *right, unsigned long data)
{
	struct thread_create_arg args;
	struct task *task;
	int ret;

	ret = copy_from_user(&args, (void *)data,
			sizeof(struct thread_create_arg));
	if (ret <= 0)
		return -EFAULT;

	task = create_task_for_process(current_proc, args.func,
			args.user_sp, args.prio, args.aff, args.flags);
	if (!task)
		return -EBUSY;

	kobject_init(&task->kobj, KOBJ_TYPE_THREAD,
			KOBJ_RIGHT_NONE, (unsigned long)task);
	*kobj = &task->kobj;
	*right = KOBJ_RIGHT_WRITE;
	task->kobj.ops = &thread_kobj_ops;

	return 0;
}
DEFINE_KOBJECT(thread, KOBJ_TYPE_THREAD, thread_create);
