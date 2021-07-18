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

struct poll_event *alloc_poll_event(void)
{
	struct poll_event_kernel *p;

	p = zalloc(sizeof(struct poll_event_kernel));
	if (!p)
		return NULL;
	p->release = 1;

	return &p->event;
}

int poll_event_send_static(tid_t tid, struct poll_event_kernel *evk)
{
	struct task *task = get_task_by_tid(tid);
	unsigned long flags;
	int wakeup = 0;

	/*
	 * task is exited ?
	 */
	if (!task)
		return -ENOENT;

	spin_lock_irqsave(&task->poll_lock, flags);
	list_add_tail(&task->poll_event_list, &evk->list);
	if ((task->stat == TASK_STAT_WAIT_EVENT) &&
			(task->wait_event == (unsigned long)&task->poll_event_list))
		wakeup = 1;
	spin_unlock_irqrestore(&task->poll_lock, flags);

	if (wakeup)
		wake_up(task, 0);

	return 0;
}

int poll_event_send_with_data(tid_t tid, int ev,
		handle_t handle, void *data, int len)
{
	struct poll_event_kernel *p;
	
	p = (struct poll_event_kernel *)alloc_poll_event();
	if (!p)
		return -ENOMEM;
	p->event.event = ev;
	p->event.handle = handle;
	p->release = 1;

	if (data && (len > 0) && (len < POLL_EVENT_DATA_SIZE))
		memcpy(p->event.data, data, len);

	return poll_event_send_static(tid, p);
}

int poll_event_send(tid_t tid, int ev, handle_t handle)
{
	return poll_event_send_with_data(tid, ev, handle, NULL, 0);
}

static int copy_poll_event_to_user(struct poll_event __user *events,
		struct list_head *head, int cnt)
{
	struct poll_event_kernel *pevent, *tmp;
	int ret;

	list_for_each_entry_safe(pevent, tmp, head, list) {
		list_del(&pevent->list);
		ret = copy_to_user(events, &pevent->event,
				sizeof(struct poll_event));
		if (ret <= 0) {
			/*
			 * the process is meet memory issue, will kill it here. send
			 * an event to the root service to handle this. TBD
			 */
			// task_die();
		}

		/*
		 * free the epoll event's memory
		 */
		if (pevent->release)
			free(pevent);
	}

	return cnt;
}

int sys_poll_wait(struct poll_event __user *events,
		int max_event, uint32_t timeout)
{
	struct task *task = current;
	unsigned long flags;
	LIST_HEAD(event_list);
	int ret = 0, cnt = 0;
	struct poll_event_kernel *pevent, *tmp;

	if (max_event <= 0)
		return -EINVAL;

	if (!access_ok(task, events, max_event *
			sizeof(struct poll_event), __VM_RW))
		return -EFAULT;

	while (ret == 0) {
		spin_lock_irqsave(&task->poll_lock, flags);
		if (is_list_empty(&task->poll_event_list)) {
			if (timeout == 0) {
				spin_unlock_irqrestore(&task->poll_lock, flags);
				return -EAGAIN;
			}
			__event_task_wait((unsigned long)&task->poll_event_list,
					TASK_EVENT_POLL, timeout);
		} else {
			list_for_each_entry_safe(pevent, tmp,
					&task->poll_event_list, list) {
				list_del(&pevent->list);
				list_add_tail(&event_list, &pevent->list);

				cnt++;
				if (cnt == max_event)
					break;
			}
		}
		spin_unlock_irqrestore(&task->poll_lock, flags);

		if (is_list_empty(&event_list)) {
			ret = wait_event();
			if (ret)
				return ret;
		} else {
			return copy_poll_event_to_user(events, &event_list, cnt);
		}
	}

	return -EAGAIN;
}
