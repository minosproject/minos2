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
#include <minos/mm.h>
#include <minos/kobject.h>
#include <minos/mutex.h>
#include <minos/uaccess.h>
#include <minos/print.h>

#define STDIO_BUF_SIZE	4096

struct kobject stdio_kobj;
static mutex_t stdio_lock;
static char stdio_buf[STDIO_BUF_SIZE];

static ssize_t stdio_send(struct kobject *kobj, void __user *data,
		size_t data_size, void __user *extra,
		size_t extra_size, uint32_t timeout)
{
	size_t left = data_size;
	int copy;
	int ret = 0;

	if (left <=0 )
		return 0;

	mutex_pend(&stdio_lock, 0);

	while (left > 0) {
		copy = left > STDIO_BUF_SIZE ? STDIO_BUF_SIZE : left;
		ret = copy_from_user(stdio_buf, data, copy);
		if (ret <= 0)
			goto out;

		puts(stdio_buf, copy);
		left -= copy;
		data += copy;
	}

	ret = data_size;

out:
	mutex_post(&stdio_lock);

	return ret;
}

static ssize_t stdio_recv(struct kobject *kobj, void __user *data,
		size_t data_size, void __user *extra,
		size_t extra_size, uint32_t timeout)
{
	// TBD
	return 0;
}

struct kobject_ops stdio_ops = {
	.send = stdio_send,
	.recv = stdio_recv,
};

static int stdio_kobject_init(void)
{
	kobject_init(&stdio_kobj, 0, KOBJ_TYPE_STDIO, 0, KOBJ_RIGHT_RW, 0);
	stdio_kobj.ops = &stdio_ops;
	mutex_init(&stdio_lock);

	return 0;
}
device_initcall(stdio_kobject_init);
