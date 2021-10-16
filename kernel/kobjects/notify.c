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
#include <minos/sched.h>
#include <minos/poll.h>

#define NOTIFY_RIGHT		(KOBJ_RIGHT_RW)
#define NOTIFY_RIGHT_MASK	(KOBJ_RIGHT_READ)

static long notify_kobj_send(struct kobject *kobj, void __user *data,
			size_t data_size, void __user *extra,
			size_t extra_size, uint32_t timeout)
{
	unsigned long msg[3];
	int ret;

	if (extra_size > sizeof(msg))
		return -E2BIG;

	memset(msg, 0, sizeof(msg));
	ret = copy_from_user(msg, extra, extra_size);
	if (ret < 0)
		return ret;

	poll_event_send_with_data(kobj->poll_struct, EV_IN, 0,
			msg[0], msg[1], msg[2]);

	return 0;
}

struct kobject_ops notify_kobj_ops = {
	.send		= notify_kobj_send,
};

int notify_create(struct kobject **kobjr, right_t *right, unsigned long data)
{
	struct kobject *kobj;

	kobj = zalloc(sizeof(struct kobject));
	if (!kobj)
		return -ENOMEM;

	kobject_init(kobj, KOBJ_TYPE_NOTIFY, NOTIFY_RIGHT_MASK, 0);
	kobj->ops = &notify_kobj_ops;
	*kobjr = kobj;
	*right = NOTIFY_RIGHT;

	return 0;
}
DEFINE_KOBJECT(notify, KOBJ_TYPE_NOTIFY, notify_create);
