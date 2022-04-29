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
#include <minos/sched.h>
#include <uspace/poll.h>
#include <uspace/kobject.h>
#include <uspace/uaccess.h>
#include <uspace/iqueue.h>
#include <uspace/proc.h>

#include "kobject_copy.h"

#define IQ_STAT_CLOSED 1
#define IQ_STAT_OPENED 0

#define KOBJ_IN_PROCESSING ((void *)-1)

long iqueue_recv(struct iqueue *iqueue, void __user *data,
		size_t data_size, size_t *actual_data, void __user *extra,
		size_t extra_size, size_t *actual_extra, uint32_t timeout)
{
	struct imsg *imsg = NULL;
	long ret = 0;

	if (iqueue->wstate == IQ_STAT_CLOSED)
		return -EIO;

	if (timeout != 0) {
		ret = sem_pend(&iqueue->isem, timeout);
		if (ret < 0)
			return ret;
	}

	spin_lock(&iqueue->lock);
	if (!is_list_empty(&iqueue->pending_list)) {
		imsg = list_first_entry(&iqueue->pending_list, struct imsg, list);
		list_del(&imsg->list);
	} else {
		ret = -EAGAIN;
	}
	spin_unlock(&iqueue->lock);
	if (ret)
		return ret;

	/*
	 * change the imsg's state then also check whether it
	 * meets error.
	 */
	ret = cmpxchg(&imsg->state, IMSG_STATE_INIT, IMSG_STATE_IN_PROCESS);
	if (ret != IMSG_STATE_INIT)
		return -EIO;

	/*
	 * read the data from this task. if the task's data is wrong
	 * wake up this write task directly. otherwise mask this task
	 * as current pending task and waitting for reply.
	 */
	ret = kobject_copy_ipc_payload(current, imsg->data,
			actual_data, actual_extra, 1, 0);
	if (ret < 0) {
		imsg->retcode = ret;
		smp_wmb();
		imsg->submit = 1;

		wake(&imsg->ievent, 0);
		return -EAGAIN;
	}

	spin_lock(&iqueue->lock);
	list_add_tail(&iqueue->processing_list, &imsg->list);
	ret = imsg->token;
	imsg->submit = 1;
	spin_unlock(&iqueue->lock);

	return ret;
}

long iqueue_send(struct iqueue *iqueue, void __user *data, size_t data_size,
		void __user *extra, size_t extra_size, uint32_t timeout)
{
	struct poll_struct *ps = iqueue->kobj->poll_struct;
	struct imsg imsg;
	long ret, status;

	/*
	 * setup the information which the task need waitting for
	 * for. If the kobject has been closed, return directly.
	 */
	spin_lock(&iqueue->lock);
	if (iqueue->rstate == IQ_STAT_CLOSED) {
		spin_unlock(&iqueue->lock);
		return -EOTHERSIDECLOSED;
	}
	imsg_init(&imsg, current);
	list_add_tail(&iqueue->pending_list, &imsg.list);
	spin_unlock(&iqueue->lock);

	/*
	 * if the releated kobject event is not polled, try
	 * to wake up the reading task.
	 */
	ret = poll_event_send(ps, EV_IN);
	if (ret == -EAGAIN)
		sem_post(&iqueue->isem);

	ret = wait_event(&imsg.ievent, imsg.token == 0, timeout);
	if (ret == 0)
		return imsg.retcode;

	status = cmpxchg(&imsg.state, IMSG_STATE_INIT, IMSG_STATE_ERROR);
	if (status == IMSG_STATE_INIT)
		goto out;

	/*
	 * wait read task to finish the processing of this request.
	 */
	while (imsg.submit == 0)
		sched();
out:
	/*
	 * the writer has been teminated or timedout, need delete
	 * this request from the pending list or processing list.
	 */
	spin_lock(&iqueue->lock);
	if (current->list.next != NULL) {
		list_del(&imsg.list);
		ret = 0;
	} else {
		ret = -EAGAIN;
	}
	spin_unlock(&iqueue->lock);

	/*
	 * rewait if the msg can be handled.
	 */
	if (ret)
		ret = wait_event(&imsg.ievent, imsg.token == 0, timeout);

	return imsg.retcode;
}

int iqueue_reply(struct iqueue *iqueue, right_t right,
		long token, long errno, handle_t fd, right_t fd_right)
{
	struct imsg *imsg, *tmp;
	struct task *task;

	/*
	 * find the task who are waitting the reply token, and wake
	 * up it with the error code.
	 */
	spin_lock(&iqueue->lock);
	list_for_each_entry_safe(imsg, tmp, &iqueue->processing_list, list) {
		if (imsg->token == token) {
			list_del(&imsg->list);
			break;
		}
	}
	spin_unlock(&iqueue->lock);

	if (!imsg)
		return -ENOENT;

	if (fd > 0) {
		task = (struct task *)imsg->data;
		errno = send_handle(current_proc, task_to_proc(task), fd, fd_right);
	}

	imsg->retcode = errno;
	smp_wmb();
	imsg->token = 0;

	wake(&imsg->ievent, 0);

	return 0;
}

static void wake_all_writer(struct iqueue *iqueue, int errno)
{
	struct imsg *imsg, *tmp;

	spin_lock(&iqueue->lock);
	list_for_each_entry_safe(imsg, tmp, &iqueue->pending_list, list) {
		list_del(&imsg->list);
		imsg->token = 0;
		wake_abort(&imsg->ievent);
	}

	list_for_each_entry_safe(imsg, tmp, &iqueue->processing_list, list) {
		list_del(&imsg->list);
		imsg->token = 0;
		wake_abort(&imsg->ievent);
	}
	spin_unlock(&iqueue->lock);
}

int iqueue_close(struct iqueue *iqueue, right_t right, struct process *proc)
{
	if (right & KOBJ_RIGHT_READ) {
		iqueue->rstate = IQ_STAT_CLOSED;
		smp_wmb();
		wake_all_writer(iqueue, -EIO);
	} else if (right & KOBJ_RIGHT_WRITE){
		if (!iqueue->mutil_writer) {
			iqueue->wstate = IQ_STAT_CLOSED;
			smp_wmb();
			/*
			 * Fix me, need to fix race condition.
			 */
			sem_pend_abort(&iqueue->isem, OS_EVENT_OPT_BROADCAST);
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
	sem_init(&iq->isem, 0);
}
