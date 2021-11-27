/*
 * Copyright (C) 2018 Min Le (lemin9538@gmail.com)
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
#include <minos/poll.h>
#include <minos/task.h>
#include <minos/string.h>
#include <minos/sched.h>
#include <minos/mm.h>
#include <minos/event.h>
#include <minos/kobject.h>
#include <minos/task.h>
#include <minos/vspace.h>
#include <minos/uaccess.h>

#define POLLHUB_RIGHT		(KOBJ_RIGHT_RO | KOBJ_RIGHT_CTL)
#define POLLHUB_RIGHT_MASK	(0)

#define to_poll_hub(kobj)	\
	(struct poll_hub *)kobj->data

struct poll_event *alloc_poll_event(void)
{
	struct poll_event_kernel *p;

	p = zalloc(sizeof(struct poll_event_kernel));
	if (!p)
		return NULL;
	p->release = 1;

	return &p->event;
}

int poll_event_send_static(struct pevent_item *pi, struct poll_event_kernel *evk)
{
	struct poll_hub *peh = pi->poller;
	struct task *task;
	unsigned long flags;

	spin_lock_irqsave(&peh->lock, flags);
	list_add_tail(&peh->event_list, &evk->list);
	task = peh->task;
	spin_unlock_irqrestore(&peh->lock, flags);

	/*
	 * wake up the waitter, if has.
	 */
	if (task && (task->stat == TASK_STAT_WAIT_EVENT) &&
			(task->wait_event == (unsigned long)peh))
		wake_up(task, 0);

	return 0;
}

int poll_event_send_with_data(struct poll_struct *ps, int ev, int type,
		uint64_t data0, uint64_t data1, uint64_t data2)
{
	struct poll_event *pe;
	struct pevent_item *pi;
	int ret = 0;

	if (!ps)
		return -EAGAIN;

	pi = ps->pevents[ev];
	smp_rmb();

	/*
	 * need aquire the spinlock of the poll_struct ?
	 */
	while (pi) {
		pe = alloc_poll_event();
		if (!pe)
			return -ENOMEM;

		pe->events = (1 << ev);
		pe->data.pdata = pi->data;
		pe->data.type = type;
		pe->data.data0 = data0;
		pe->data.data1 = data1;
		pe->data.data2 = data2;

		ret += poll_event_send_static(pi, (struct poll_event_kernel *)pe);
		pi = pi->next;
	}

	return ret;
}

int poll_event_send(struct poll_struct *ps, int ev)
{
	return poll_event_send_with_data(ps, ev, 0, 0, 0, 0);
}

static int copy_poll_event_to_user(struct poll_event __user *events,
		struct list_head *head, int cnt)
{
	struct poll_event_kernel *pevent, *tmp;
	int ret, num = 0;

	list_for_each_entry_safe(pevent, tmp, head, list) {
		list_del(&pevent->list);
		ret = copy_to_user(&events[num++], &pevent->event,
				sizeof(struct poll_event));
		/*
		 * free the epoll event's memory
		 */
		if (pevent->release)
			free(pevent);
		ASSERT(ret > 0);
	}

	return cnt;
}

static int __poll_hub_read(struct poll_hub *peh,
		struct poll_event __user *events,
		int max_event, uint32_t timeout)
{
	struct poll_event_kernel *pevent, *tmp;
	unsigned long flags;
	LIST_HEAD(event_list);
	int ret = 0, cnt = 0;

	if (max_event <= 0)
		return -EINVAL;

	if (!user_ranges_ok((void *)events,
				max_event * sizeof(struct poll_event)))
		return -EFAULT;

	while (ret == 0) {
		spin_lock_irqsave(&peh->lock, flags);

		/*
		 * some task in this process is aready waitting data on
		 * this poll_hub, return -EAGAIN.
		 */
		if ((peh->task != NULL) && (peh->task != current))
			goto out;

		peh->task = NULL;

		if (is_list_empty(&peh->event_list)) {
			if (timeout == 0)
				goto out;

			peh->task = current;
			__event_task_wait((unsigned long)peh, TASK_EVENT_POLL, timeout);
			spin_unlock_irqrestore(&peh->lock, flags);

			/*
			 * the poll_hub kobject is only read/write by itself
			 * other process will not see it, so do not need to
			 * consider the case of EABORT
			 */
			ret = wait_event();
			if (ret) {
				peh->task = NULL;
				return ret;
			}
			continue;
		}

		list_for_each_entry_safe(pevent, tmp, &peh->event_list, list) {
			list_del(&pevent->list);
			list_add_tail(&event_list, &pevent->list);

			cnt++;
			if (cnt == max_event)
				break;
		}
		spin_unlock_irqrestore(&peh->lock, flags);

		if (!is_list_empty(&event_list)) {
			ret = copy_poll_event_to_user(events, &event_list, cnt);
			return ret;
		}
	}

out:
	spin_unlock_irqrestore(&peh->lock, flags);
	return -EAGAIN;
}

static long poll_hub_read(struct kobject *kobj, void __user *data, size_t data_size,
		size_t *actual_data, void __user *extra, size_t extra_size,
		size_t *actual_extra, uint32_t timeout)
{
	struct poll_hub *peh = to_poll_hub(kobj);
	int cnt;

	cnt = __poll_hub_read(peh, data,
			data_size / sizeof(struct poll_event), timeout);
	if (cnt <= 0)
		return cnt;

	*actual_data = cnt * sizeof(struct poll_event);

	return 0;
}

static void poll_hub_release(struct kobject *kobj)
{
	struct poll_hub *peh = to_poll_hub(kobj);
	struct poll_event_kernel *pek, *tmp;

	/*
	 * currently only kernel can access this kobject
	 * now. so do not need to acquire the poll_hub's
	 * spinlock here.
	 */
	list_for_each_entry_safe(pek, tmp, &peh->event_list, list) {
		list_del(&pek->list);
		if (pek->release)
			free(pek);
	}

	free(peh);
}

static int poll_hub_close(struct kobject *kobj, right_t right)
{
	return 0;
}

static struct pevent_item *find_pevent_item(struct poll_struct *ps, int ev, struct poll_hub *ph)
{
	struct pevent_item *pi = ps->pevents[ev];

	while (pi) {
		if (pi->poller == ph)
			return pi;
		pi = pi->next;
	}

	return NULL;
}

static inline void add_new_pevent(struct poll_struct *ps, int ev, struct pevent_item *pi)
{
	struct pevent_item *head = ps->pevents[ev];

	pi->next = head;
	ps->pevents[ev] = pi;
	mb();
}

static struct pevent_item * find_and_del_pevent_item(struct poll_struct *ps,
		int ev, struct poll_hub *ph)
{
	struct pevent_item *pi = ps->pevents[ev];
	struct pevent_item *tmp = NULL;

	while (pi) {
		if (pi->poller == ph) {
			if (tmp == NULL)
				ps->pevents[ev] = pi->next;
			else
				tmp->next = pi->next;

			mb();
			return pi;
		}

		tmp = pi;
		pi = pi->next;
	}

	return NULL;
}

void release_poll_struct(struct kobject *kobj)
{
	struct poll_struct *ps = kobj->poll_struct;
	struct pevent_item *pi, *tmp;
	struct poll_hub *ph;
	int i;

	if (!ps)
		return;

	for (i = 0; i < EV_MAX; i++) {
		pi = ps->pevents[i];
		while (pi) {
			tmp = pi->next;
			ph = pi->poller;
			free(pi);
			kobject_put(&ph->kobj);
			pi = tmp;
		}
	}

	free(ps);
}

static int __poll_hub_ctl(struct poll_hub *ph, struct kobject *ksrc,
		int right, int op, struct poll_event *uevent)
{
	int events, ev;
	struct pevent_item *ei;
	struct poll_struct *ps;
	int i, ret = 0;

	spin_lock(&ksrc->lock);

	ps = ksrc->poll_struct;
	if (ps == NULL) {
		ps = zalloc(sizeof(struct poll_struct));
		if (ps == NULL) {
			spin_unlock(&ksrc->lock);
			return -ENOMEM;
		}

		ksrc->poll_struct = ps;
	}

	events = uevent->events;

	for (i = 0; i < EV_MAX; i++) {
		ev = events & (1 << i);
		if (!ev)
			continue;

		switch (op) {
		case KOBJ_POLL_OP_ADD:
			ei = find_pevent_item(ps, i, ph);
			if (!ei) {
				ret = kobject_poll(&ph->kobj, ksrc, ev, 1);
				if (ret)
					break;

				ei = malloc(sizeof(struct pevent_item));
				if (!ei) {
					pr_err("failed to allocate new pevent item\n");
					ret = -ENOMEM;
					goto out;
				}

				ei->poller = ph;
				ei->data = uevent->data.pdata;
				add_new_pevent(ps, i, ei);
				kobject_get(&ph->kobj);
			}
			break;
		case KOBJ_POLL_OP_MOD:
			ei = find_pevent_item(ps, i, ph);
			if (ei)
				ei->data = uevent->data.pdata;
			else
				pr_err("epoll_mod %d is not enabled\n", ev);
			break;
		case KOBJ_POLL_OP_DEL:
			ei = find_and_del_pevent_item(ps, i, ph);
			if (ei) {
				kobject_poll(&ph->kobj, ksrc, ev, 0);
				free(ei);
				kobject_put(&ph->kobj);
			} else {
				pr_err("epoll_del %d is not enabled\n", ev);
			}
			break;
		default:
			pr_err("unsupport epoll action\n");
			break;
		}
	}

out:
	spin_unlock(&ksrc->lock);

	return ret;
}

static int poll_hub_check_right(int events, right_t right)
{
	events &= POLL_EVENT_MASK;
	if (events == 0)
		return -EINVAL;

	if ((events & POLL_READ_RIGHT_EVENT) && !(right & KOBJ_RIGHT_READ))
		return -EPERM;

	if ((events & POLL_WRITE_RIGHT_EVENT) && !(right & KOBJ_RIGHT_WRITE))
		return -EPERM;

	return 0;
}

static long poll_hub_ctl(struct kobject *kobj, int op, unsigned long data)
{
	struct poll_hub *ph = (struct poll_hub *)kobj->data;
	struct poll_event uevent;
	struct kobject *kobj_polled;
	right_t right;
	int ret;

	ret = copy_from_user(&uevent, (void __user *)data,
			sizeof(struct poll_event));
	if (ret <= 0)
		return ret;

	ret = get_kobject_from_process(current_proc,
			uevent.data.fd, &kobj_polled, &right);
	if (ret)
		return -ENOENT;

	ret = poll_hub_check_right(uevent.events, right);
	if (ret)
		return -EPERM;

	ret = __poll_hub_ctl(ph, kobj_polled, right, op, &uevent);
	put_kobject(kobj_polled);

	return ret;
}

static struct kobject_ops poll_hub_ops = {
	.recv		= poll_hub_read,
	.release	= poll_hub_release,
	.close		= poll_hub_close,
	.ctl		= poll_hub_ctl,
};

static int poll_hub_create(struct kobject **kobj, right_t *right, unsigned long data)
{
	struct poll_hub *peh;

	peh = zalloc(sizeof(struct poll_hub));
	if (!peh)
		return -ENOMEM;

	init_list(&peh->event_list);
	spin_lock_init(&peh->lock);
	kobject_init(&peh->kobj, KOBJ_TYPE_POLLHUB,
			POLLHUB_RIGHT_MASK, (unsigned long)peh);
	peh->kobj.ops = &poll_hub_ops;
	*kobj = &peh->kobj;
	*right = POLLHUB_RIGHT;

	return 0;
}
DEFINE_KOBJECT(poll_hub, KOBJ_TYPE_POLLHUB, poll_hub_create);
