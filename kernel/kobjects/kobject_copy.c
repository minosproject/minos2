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

struct kobject_rw_arg {
	void __user *data;
	size_t data_size;
};

struct syscall_regs {
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
};

static inline struct syscall_regs *task_syscall_regs(struct task *task)
{
	return (struct syscall_regs *)&task->user_gp_regs->x0;
}

ssize_t kobject_copy_ipc_data(struct task *tdst, struct task *tsrc, int check_size)
{
	struct syscall_regs *src_regs, *dst_regs;
	void __user *dst, *src;
	size_t dsize, ssize;
	size_t copy;

	src_regs = task_syscall_regs(tsrc);
	src = (void *)src_regs->a1;
	ssize = (size_t)src_regs->a2;

	dst_regs = task_syscall_regs(tdst);
	dst = (void *)dst_regs->a1;
	dsize = (size_t)dst_regs->a2;

	if (check_size && (dsize != ssize))
		return -EINVAL;

	copy = MIN(dsize, ssize);
	if (copy == 0)
		return 0;

	return copy_user_to_user(&tdst->proc->vspace,
			dst, &tsrc->proc->vspace, src, copy);
}

ssize_t kobject_copy_extra_data(struct task *tdst, struct task *tsrc, int check_size)
{
	struct syscall_regs *src_regs, *dst_regs;
	void __user *dst, *src;
	size_t dsize, ssize;
	size_t copy;

	src_regs = task_syscall_regs(tsrc);
	src = (void *)src_regs->a3;
	ssize = (size_t)src_regs->a4;

	dst_regs = task_syscall_regs(tdst);
	dst = (void *)dst_regs->a3;
	dsize = (size_t)dst_regs->a4;

	if (check_size && (dsize != ssize))
		return -EINVAL;

	copy = MIN(dsize, ssize);
	if (copy == 0)
		return 0;

	return copy_user_to_user(&tdst->proc->vspace,
			dst, &tsrc->proc->vspace, src, copy);
}

ssize_t kobject_copy_ipc_payload(struct task *dtsk, struct task *ttsk,
		size_t *actual_data, size_t *actual_extra,
		int check_data, int check_extra)
{
	ssize_t ret;

	ret = kobject_copy_ipc_data(dtsk, ttsk, check_data);
	if (ret < 0)
		return ret;
	*actual_data = ret;

	ret = kobject_copy_extra_data(dtsk, ttsk, check_extra);
	if (ret >= 0) {
		*actual_extra = ret;
		ret = 0;
	}

	return ret;
}
