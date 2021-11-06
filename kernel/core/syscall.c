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
#include <minos/irq.h>
#include <minos/sched.h>
#include <minos/vspace.h>
#include <minos/proc.h>
#include <minos/arch.h>
#include <minos/console.h>
#include <minos/kobject.h>
#include <minos/uaccess.h>
#include <minos/poll.h>

void sys_sched_yield(void)
{
	local_irq_enable();
	sched();
	local_irq_disable();
}

long sys_kobject_close(handle_t handle)
{
	struct kobject *kobj;
	right_t right;
	long ret;

	/*
	 * release the handle first, then other thread in
	 * this process can not see this kobject now. if one
	 * thread in this process called this successfully
	 * other thread can not get ok from release_handle.
	 */
	ret = release_handle(handle, &kobj, &right);
	if (ret)
		return ret;

	return kobject_close(kobj, right);
}

handle_t sys_kobject_create(int type, unsigned long data)
{
	struct kobject *kobj;
	right_t right;
	int ret;

	ret = kobject_create(type, &kobj, &right, data);
	if (ret)
		return ret;

	/*
	 * visable for all the threads in this process, and
	 * the owner of this kobject have the GRANT right for
	 * this kobject.
	 */
	return alloc_handle(kobj, right);
}

int sys_kobject_open(handle_t handle)
{
	struct kobject *kobj;
	right_t right;
	int ret;

	ret = get_kobject(handle, &kobj, &right);
	if (ret)
		return ret;

	ret = kobject_open(kobj, handle, right);
	put_kobject(kobj);

	return ret;
}

long sys_kobject_recv(handle_t handle, void __user *data, size_t data_size,
		size_t *actual_data, void __user *extra, size_t extra_size,
		size_t *actual_extra, uint32_t timeout)
{
	struct kobject *kobj;
	right_t right;
	long ret;

	ret = get_kobject(handle, &kobj, &right);
	if (ret)
		return ret;

	if (!(right & KOBJ_RIGHT_READ)) {
		ret = -EPERM;
		goto out;
	}

	ret = kobject_recv(kobj, data, data_size, actual_data, extra,
			extra_size, actual_extra, timeout);
out:
	put_kobject(kobj);
	return ret;
}

long sys_kobject_send(handle_t handle, void __user *data, size_t data_size,
		void __user *extra, size_t extra_size, uint32_t timeout)
{
	struct kobject *kobj;
	right_t right;
	long ret;

	ret = get_kobject(handle, &kobj, &right);
	if (ret)
		return ret;

	if (!(right & KOBJ_RIGHT_WRITE)) {
		ret = -EPERM;
		goto out;
	}

	ret = kobject_send(kobj, data, data_size, extra, extra_size, timeout);
out:
	put_kobject(kobj);
	return ret;
}

/*
 * kobject reply can reply a fd to the target process
 * who obtain this handle. if need to reply a fd.
 */
long sys_kobject_reply(handle_t handle, unsigned long token,
		long err_code, handle_t fd, right_t fd_right)
{
	struct kobject *kobj;
	right_t right;
	long ret;

	ret = get_kobject(handle, &kobj, &right);
	if (ret)
		return ret;

	if (!(right & KOBJ_RIGHT_READ))
		return -EPERM;

	ret = kobject_reply(kobj, right, token, err_code, fd, fd_right);
	put_kobject(kobj);

	return ret;
}

long sys_kobject_ctl(handle_t handle, int req, unsigned long data)
{
	struct kobject *kobj;
	right_t right;
	long ret;

	ret = get_kobject(handle, &kobj, &right);
	if (ret)
		return ret;

	if (!(right & KOBJ_RIGHT_CTL)) {
		ret = -EPERM;
		goto out;
	}

	ret = kobject_ctl(kobj, right, req, data);
out:
	put_kobject(kobj);

	return ret;
}

int sys_kobject_mmap(handle_t handle,
		void **addr, unsigned long *map_size)
{
	struct kobject *kobj;
	right_t right;
	long ret;

	ret = get_kobject(handle, &kobj, &right);
	if (ret)
		return ret;

	if (!(right & KOBJ_RIGHT_MMAP))
		goto out;

	ret = kobject_mmap(kobj, right, addr, map_size);
out:
	put_kobject(kobj);
	return ret;
}

int sys_kobject_munmap(handle_t handle)
{
	struct kobject *kobj;
	right_t right;
	int ret;

	ret = get_kobject(handle, &kobj, &right);
	if (ret)
		return ret;

	if (!(right & KOBJ_RIGHT_MMAP)) {
		ret = -EPERM;
		goto out;
	}

	ret = kobject_munmap(kobj, right);
out:
	put_kobject(kobj);
	return ret;
}
