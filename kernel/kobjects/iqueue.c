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

#include "kobject_copy.h"

#define IQ_STAT_CLOSED 1
#define IQ_STAT_OPENED 0

#define KOBJ_IN_PROCESSING ((void *)-1)

long iqueue_recv(struct iqueue *iqueue, void __user *data,
		size_t data_size, size_t *actual_data, void __user *extra,
		size_t extra_size, size_t *actual_extra, uint32_t timeout)
{
	struct kobject *pending = NULL;
	long ret = 0, status = TASK_STAT_PEND_OK;
	struct task *writer;

	spin_lock(&iqueue->lock);
	for (;;) {
		/*
		 * only one task can wait for data on the endpoint, if
		 * there is already reading task, return -EBUSY.
		 * if wait_event fail, then return error, before return
		 * need set the recv_task to NULL.
		 */
		if ((iqueue->recv_task != NULL) && (iqueue->recv_task != current)) {
			spin_unlock(&iqueue->lock);
			return -EBUSY;
		}

		/*
		 * clear the recv_task in iqueue, later this value will
		 * be set again if need sleep.
		 */
		iqueue->recv_task = NULL;

		if (!task_stat_pend_ok(status)) {
			spin_unlock(&iqueue->lock);
			return -EABORT;
		}

		if (!is_list_empty(&iqueue->pending_list)) {
			pending = list_first_entry(&iqueue->pending_list, struct kobject, list);
			list_del(&pending->list);
			pending->list.next = KOBJ_IN_PROCESSING;
		} else if (iqueue->writer_stat == IQ_STAT_CLOSED){
			spin_unlock(&iqueue->lock);
			return -EOTHERSIDECLOSED;
		} else if (timeout == 0) {
			spin_unlock(&iqueue->lock);
			return -EAGAIN;
		} else {
			iqueue->recv_task = current;
		}

		if (pending != NULL)
			break;
		else
			status = wait_event_locked(iqueue->kobj->type,
					timeout, &ret, &iqueue->lock);
	}
	spin_unlock(&iqueue->lock);

	/*
	 * read the data from this task. if the task's data is wrong
	 * wake up this write task directly. otherwise mask this task
	 * as current pending task and waitting for reply.
	 */
	writer = (struct task *)pending->data;
	ret = kobject_copy_ipc_payload(current, writer, actual_data, actual_extra, 1, 0);
	if (ret < 0) {
		pending->list.next = NULL;
		smp_wmb();

		wake_up(writer, ret);
		goto out;
	}

	spin_lock(&iqueue->lock);
	ASSERT(pending->list.next == KOBJ_IN_PROCESSING);
	list_add_tail(&iqueue->processing_list, &pending->list);
	ret = (long)writer->wait_event;
out:
	spin_unlock(&iqueue->lock);

	return ret;
}

long iqueue_send(struct iqueue *iqueue, void __user *data, size_t data_size,
		void __user *extra, size_t extra_size, uint32_t timeout)
{
	struct poll_struct *ps = iqueue->kobj->poll_struct;
	struct task *task;
	long ret, status;

	/*
	 * setup the information which the task need waitting for
	 * for. If the kobject has been closed, return directly.
	 */
	spin_lock(&iqueue->lock);
	if (iqueue->reader_stat == IQ_STAT_CLOSED) {
		spin_unlock(&iqueue->lock);
		return -EOTHERSIDECLOSED;
	}
	list_add_tail(&iqueue->pending_list, &current->kobj.list);
	__event_task_wait(new_event_token(), TASK_EVENT_KOBJ_REPLY, timeout);
	spin_unlock(&iqueue->lock);

	/*
	 * if the releated kobject event is not polled, try
	 * to wake up the reading task.
	 *
	 * the case of wake up here is:
	 * 1 - reader got the lock first, the recv_task will set
	 * 2 - writer got the lock first, the reader can see the
	 *     data which reader add.
	 * so here do not need require the spinlock.
	 */
	ret = poll_event_send(ps, EV_IN);
	if (ret == -EAGAIN) {
		task = iqueue->recv_task;
		if (task)
			wake_up(task, 0);
	}

	status = wait_event(&ret);
	if (task_stat_pend_ok(status))
		return ret;

	/*
	 * wait read task to finish the processing of this request.
	 */
	while (current->kobj.list.next != KOBJ_IN_PROCESSING)
		cpu_relax();

	/*
	 * the writer has been teminated or timedout, need delete
	 * this request from the pending list or processing list.
	 */
	spin_lock(&iqueue->lock);
	ASSERT(current->kobj.list.next != KOBJ_IN_PROCESSING);
	if (current->kobj.list.next != NULL)
		list_del(&current->kobj.list);
	spin_unlock(&iqueue->lock);

	return ret;
}

int iqueue_reply(struct iqueue *iqueue, right_t right,
		long token, long errno, handle_t fd, right_t fd_right)
{
	struct kobject *wk, *tmp;
	struct task *task = NULL;

	/*
	 * find the task who are waitting the reply token, and wake
	 * up it with the error code.
	 */
	spin_lock(&iqueue->lock);
	list_for_each_entry_safe(wk, tmp, &iqueue->processing_list, list) {
		task = (struct task *)wk->data;
		if (task->wait_event == token) {
			list_del(&wk->list);
			break;
		}
	}
	spin_unlock(&iqueue->lock);

	if (task) {
		if (fd > 0) {
			errno = send_handle(current_proc, task->proc,
					fd, fd_right);
		}
		wake_up(task, errno);
	} else {
		return -ENOENT;
	}

	return 0;
}

static void wake_all_writer(struct iqueue *iqueue, int errno)
{
	struct kobject *kobj, *tmp;

	list_for_each_entry_safe(kobj, tmp, &iqueue->pending_list, list) {
		list_del(&kobj->list);
		wake_up((struct task *)kobj->data, errno);
	}

	list_for_each_entry_safe(kobj, tmp, &iqueue->processing_list, list) {
		list_del(&kobj->list);
		wake_up((struct task *)kobj->data, errno);
	}
}

int iqueue_close(struct iqueue *iqueue, right_t right, struct process *proc)
{
	if (right & KOBJ_RIGHT_READ) {
		spin_lock(&iqueue->lock);
		iqueue->reader_stat = IQ_STAT_CLOSED;
		wake_all_writer(iqueue, -EIO);
		spin_unlock(&iqueue->lock);
	} else if (right & KOBJ_RIGHT_WRITE){
		if (!iqueue->mutil_writer) {
			iqueue->writer_stat = IQ_STAT_CLOSED;
			smp_wmb();
		}
	}

	return 0;
}

void iqueue_init(struct iqueue *iq, int mutil_writer, struct kobject *kobj)
{
	ASSERT((iq != NULL) && (kobj != NULL));
	iq->mutil_writer = !!mutil_writer;
	iq->kobj = kobj;
	spin_lock_init(&iq->lock);
	init_list(&iq->pending_list);
	init_list(&iq->processing_list);
}
