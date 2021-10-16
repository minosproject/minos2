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
	*right = KOBJ_RIGHT_RW;

	return 0;
}
DEFINE_KOBJECT(thread, KOBJ_TYPE_THREAD, thread_create);
