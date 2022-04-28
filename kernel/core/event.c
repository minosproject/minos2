/*
 * Copyright (C) 2019 Min Le (lemin9538@gmail.com)
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
#include <minos/task.h>
#include <minos/sched.h>
#include <minos/event.h>
#include <minos/mm.h>
#include <minos/smp.h>

static atomic_t event_token = { 1 };
static atomic_t event_token_gen = { 0 };

uint32_t new_event_token(void)
{
	uint32_t value;

	while (1) {
		value = (uint32_t)atomic_inc_return_old(&event_token);
		if (value == 0)
			atomic_inc(&event_token_gen);
		else
			break;
	}

	return value;
}

void event_init(struct event *event, int type, void *pdata)
{
	event->type = type;
	spin_lock_init(&event->lock);
	init_list(&event->wait_list);
	event->data = pdata;
	event->owner = 0;
}

void __wait_event(void *ev, int mode, uint32_t to)
{
	struct task *task = current;
	struct event *event;

	do_not_preempt();

	/*
	 * the process of flag is different with other IPC
	 * method
	 */
	if (mode == OS_EVENT_TYPE_FLAG) {
		task->flag_node = ev;
	} else {
		event = (struct event *)ev;
		list_add_tail(&event->wait_list, &task->event_list);
	}

	/*
	 * after event_task_wait, the process will call sched()
	 * by itself, before sched() is called, the task can not
	 * be sched out, since at the same time another thread
	 * may wake up this process, which may case dead lock
	 * with current design.
	 */
	task->state = TASK_STATE_WAIT_EVENT;
	task->pend_state = TASK_STATE_PEND_OK;
	task->wait_type = mode;
	task->delay = (to == -1 ? 0 : to);
}

static inline void remove_event_waiter(struct event *ev, struct task *task)
{
	unsigned long flags;

	spin_lock_irqsave(&ev->lock, flags);
	if (task->event_list.next != NULL) {
		ASSERT(task->wait_event = (void *)ev);
		list_del(&task->event_list);
		task->event_list.next = NULL;
	}
	spin_unlock_irqrestore(&ev->lock, flags);
}

static inline struct task *get_event_waiter(struct event *ev)
{
	struct task *task;

	if (is_list_empty(&ev->wait_list))
		return NULL;

	task = list_first_entry(&ev->wait_list, struct task, event_list);
	list_del(&task->event_list);

	return task;
}

/*
 * num - the number need to wake ? <= 0 means, wakeup all.
 * will return the number of task which have been wake.
 */
int __wake_up_event_waiter(struct event *ev, long msg, int pend_state, int num)
{
	struct task *task;
	int ret, cnt = 0;

	num = (num == 0) ? 1 : num;

	do {
		task = get_event_waiter(ev);
		if (!task)
			break;

		ret = __wake_up(task, pend_state, (unsigned long)msg);
		if (ret)
			continue;

		if (++cnt == num)
			break;
	} while (1);

	return cnt;
}

struct task *wake_up_one_event_waiter(struct event *ev,
		long msg, int pend_state)
{
	struct task *task;

	do {
		task = get_event_waiter(ev);
		if (!task)
			break;
	} while (__wake_up(task, pend_state, (unsigned long)msg));

	return task;
}

void event_pend_down(void)
{
	struct task *task = current;

	task->pend_state = TASK_STATE_PEND_OK;
	task->wait_event = NULL;
	task->wait_type = 0;
	task->ipcdata = 0;
}

long __wake(struct event *ev, int pend_state, long retcode)
{
	unsigned long flags;
	struct task *task;

	spin_lock_irqsave(&ev->lock, flags);
	task = wake_up_one_event_waiter(ev, retcode, pend_state);
	spin_unlock_irqrestore(&ev->lock, flags);

	return task ? 0 : -ENOENT;
}

long do_wait_event(struct event *ev)
{
	long ret = 0;

	sched();

	switch (current->pend_state) {
	case TASK_STATE_PEND_OK:
		break;
	case TASK_STATE_PEND_TO:
	case TASK_STATE_PEND_ABORT:
	default:
		remove_event_waiter(ev, current);
		break;
	}

	ret = current->retcode;
	event_pend_down();

	return ret;
}
