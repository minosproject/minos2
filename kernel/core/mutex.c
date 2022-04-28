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
#include <minos/event.h>
#include <minos/task.h>
#include <minos/mutex.h>
#include <minos/sched.h>

int mutex_accept(mutex_t *mutex)
{
	struct task *task = current;
	int ret = -EBUSY;

	spin_lock(&mutex->lock);
	if (mutex->cnt == OS_MUTEX_AVAILABLE) {
		mutex->owner = task->tid;
		mutex->data = task;
		mutex->cnt = task->tid;
		ret = 0;
	}
	spin_unlock(&mutex->lock);

	return ret;
}

int mutex_pend(mutex_t *m, uint32_t timeout)
{
	struct task *task = current;

	might_sleep();

	/*
	 * mutex_pend and mutex_post can not be used in interrupt
	 * context.
	 */
	spin_lock(&m->lock);
	if (m->cnt == OS_MUTEX_AVAILABLE) {
		m->owner = task->tid;
		m->data = (void *)task;
		m->cnt = task->tid;
		spin_unlock(&m->lock);
		return 0;
	}
	__wait_event(TO_EVENT(m), OS_EVENT_TYPE_MUTEX, timeout);
	spin_unlock(&m->lock);
	
	return do_wait_event(TO_EVENT(m));
}

int mutex_post(mutex_t *m)
{
	struct task *task;

	ASSERT(m->owner == current->tid);

	/* 
	 * find the highest prio task to run, if there is
	 * no task, then set the mutex is available else
	 * resched
	 */
	spin_lock(&m->lock);
	task = wake_up_one_event_waiter(TO_EVENT(m), 0, TASK_STATE_PEND_OK);
	if (task == NULL) {
		m->cnt = OS_MUTEX_AVAILABLE;
		m->data = NULL;
		m->owner = 0;
	} else {
		m->owner = task->tid;
		m->data = (void *)task;
		m->cnt = task->tid;
	}
	spin_unlock(&m->lock);

	return 0;
}
