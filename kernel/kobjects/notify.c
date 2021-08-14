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

#define NOTIFY_EVENT_MAX	16
#define NOTIFY_NAME_SIZE	32
#define NOTIRY_MSG_SIZE_MAX	PAGE_SIZE

#define NOTIFY_RIGHT		(KOBJ_RIGHT_WRITE)
#define NOTIFY_RIGHT_MASK	(KOBJ_RIGHT_WRITE)

struct notify_wait_entry {
	struct poll_struct *ps;
	struct list_head list;
};

struct notify {
	spinlock_t lock;
	struct list_head wait_list;
	struct kobject kobj;
};

#define kobject_to_notify(kobj) \
	(struct notify *)(kobj)->data

static int notify_send_event(struct poll_struct *ps,
		unsigned long id, unsigned long *data)
{
	struct poll_event_kernel *evk =
		(struct poll_event_kernel *)alloc_poll_event();
	struct poll_event *event = &evk->event;

	if (!evk)
		return -ENOMEM;

	event->events = POLLIN;
	event->data.ptr = NULL;
	event->data.fd = -1;
	event->data.type = POLLIN_NOTIFY;
	event->data.data0 = data[0];
	event->data.data1 = data[1];
	event->data.data2 = data[2];

	poll_event_send_static(ps, evk);

	return 0;
}

static long notify_kobj_send(struct kobject *kobj, void __user *data,
			size_t data_size, void __user *extra,
			size_t extra_size, uint32_t timeout)
{
	struct notify *nf = (struct notify *)kobj->data;
	unsigned long event_id = (unsigned long)data;
	struct notify_wait_entry *w;
	unsigned long msg[3];
	int ret;

	if (extra_size > sizeof(msg))
		return -E2BIG;

	memset(msg, 0, sizeof(msg));
	ret = copy_from_user(msg, extra, extra_size);
	if (ret < 0)
		return ret;

	spin_lock(&nf->lock);
	list_for_each_entry(w, &nf->wait_list, list)
		ret += notify_send_event(w->ps, event_id, msg);
	spin_unlock(&nf->lock);

	return ret;
}

static int notify_add_receiver(struct notify *nf, struct poll_struct *ps)
{
	struct notify_wait_entry *we;

	we = zalloc(sizeof(struct notify_wait_entry));
	if (!we)
		return -ENOMEM;

	spin_lock(&nf->lock);
	we->ps = ps;
	list_add_tail(&nf->wait_list, &we->list);
	spin_unlock(&nf->lock);

	return 0;
}

static int notify_del_receiver(struct notify *nf, struct poll_struct *ps)
{
	struct notify_wait_entry *we, *tmp;
	int ret = -ENOENT;

	spin_lock(&nf->lock);
	list_for_each_entry_safe(we, tmp, &nf->wait_list, list) {
		if (ps == we->ps) {
			list_del(&we->list);
			ret = 0;
			break;
		}
	}
	spin_unlock(&nf->lock);

	return ret;
}

static int notify_kobj_poll(struct kobject *kobj,
		struct kobject *dst, int event, int enable)
{
	struct notify *nf = kobject_to_notify(kobj);

	if (enable)
		return notify_add_receiver(nf, &kobj->poll_struct);
	else
		return notify_del_receiver(nf, &kobj->poll_struct);
}

struct kobject_ops notify_kobj_ops = {
	.send		= notify_kobj_send,
	.poll		= notify_kobj_poll,
};

static int notify_check_right(right_t right, right_t right_req)
{
	if (right != NOTIFY_RIGHT)
		return 0;

	if (right_req != KOBJ_RIGHT_WRITE)
		return 0;

	return 1;
}

static struct kobject *notify_create(right_t right,
		right_t right_req, unsigned long data)
{
	struct notify *nf;

	if (!notify_check_right(right, right_req))
		return ERROR_PTR(-EPERM);

	nf = zalloc(sizeof(struct notify));
	if (!nf)
		return ERROR_PTR(-ENOMEM);

	spin_lock_init(&nf->lock);
	kobject_init(&nf->kobj, KOBJ_TYPE_NOTIFY, right, (unsigned long)nf);
	nf->kobj.ops = &notify_kobj_ops;

	return &nf->kobj;
}
DEFINE_KOBJECT(notify, KOBJ_TYPE_NOTIFY, notify_create);
