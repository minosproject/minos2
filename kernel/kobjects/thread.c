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

struct thread_create_arg {
	unsigned long func;
	void *user_sp;
	int prio;
	int aff;
	unsigned long flags;
};

static struct kobject *thread_create(char *str, right_t right,
		right_t right_req, unsigned long data)
{
	struct thread_create_arg args;
	struct task *task;
	int ret;

	ret = copy_from_user(&args, (void *)data, sizeof(struct thread_create_arg));
	if (ret <= 0)
		return ERROR_PTR(ENOMEM);

	task = create_task_for_process(current_proc, str,
			args.func, args.user_sp, args.prio, args.aff, args.flags);
	if (!task)
		return ERROR_PTR(ENOMEM);

	kobject_init(&task->kobj, current_pid, KOBJ_TYPE_THREAD,
			KOBJ_FLAGS_INVISABLE, KOBJ_RIGHT_NONE, (unsigned long)task);

	return &task->kobj;
}
DEFINE_KOBJECT(thread, KOBJ_TYPE_ENDPOINT, thread_create);
