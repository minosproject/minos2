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

#define EP_READER 0
#define EP_WRITER 1
#define EP_NULL 2

#define EP_STAT_CLOSED 1
#define EP_STAT_OPENED 0

#define EP_RIGHT_MASK	(KOBJ_RIGHT_MMAP | KOBJ_RIGHT_CTL)
#define EP_RIGHT	(KOBJ_RIGHT_RW | KOBJ_RIGHT_CTL)

struct endpoint {
	struct task *recv_task;			// which task is receiveing data from this endpoint.
	int status[2];				// status for the reader and writer.
	int mode;

	void *shmem;
	size_t shmem_size;

	struct kobject kobj;			// kobj for this endpoint.

	spinlock_t lock;			// spinlock to prevent below member.
	struct list_head pending_list;		// pending write task will list here.
	struct list_head processing_list;	// the task which has aready processing and waiting reply.
};

#define kobject_to_endpoint(kobj)	\
	(struct endpoint *)((kobj)->data)

#define EP_DIR(right)	\
	(right & KOBJ_RIGHT_READ) ? EP_READER : EP_WRITER

static void wake_all_ep_writer(struct endpoint *ep, int errno)
{
	struct kobject *kobj, *tmp;

	list_for_each_entry_safe(kobj, tmp, &ep->pending_list, list) {
		wake_up((struct task *)kobj->data, errno);
		list_del(&kobj->list);
	}

	list_for_each_entry_safe(kobj, tmp, &ep->processing_list, list) {
		wake_up((struct task *)kobj->data, errno);
		list_del(&kobj->list);
	}
}

static int endpoint_close(struct kobject *kobj, right_t right)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);
	int dir = EP_DIR(right);

	if ((right & KOBJ_RIGHT_RW) == 0)
		goto out;

	ep->status[dir] = EP_STAT_CLOSED;
	smp_wmb();

	if (dir == EP_READER) {
		spin_lock(&ep->lock);
		wake_all_ep_writer(ep, -EIO);
		spin_unlock(&ep->lock);
	}

out:
	if (ep->shmem)
		unmap_process_memory(current_proc, va2sva(ep->shmem), ep->shmem_size);

	return 0;
}

static long endpoint_recv(struct kobject *kobj, void __user *data,
		size_t data_size, size_t *actual_data, void __user *extra,
		size_t extra_size, size_t *actual_extra, uint32_t timeout)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);
	struct kobject *pending = NULL;
	struct task *writer;
	ssize_t ret = 0;

	for (;;) {
		spin_lock(&ep->lock);

		if (ep->status[EP_READER] == EP_STAT_CLOSED) {
			spin_unlock(&ep->lock);
			return -EIO;
		}

		if (ep->status[EP_WRITER] == EP_STAT_CLOSED) {
			spin_unlock(&ep->lock);
			return -EOTHERSIDECLOSED;
		}

		/*
		 * only one task can wait for data on the endpoint, if
		 * there is already reading task, return -EBUSY.
		 * if wait_event fail, then return error, before return
		 * need set the recv_task to NULL.
		 */
		if ((ep->recv_task != NULL) && (ep->recv_task != current)) {
			spin_unlock(&ep->lock);
			return -EBUSY;
		}

		/*
		 * clear the recv_task in endpoint, later this value will
		 * be set again if need sleep.
		 */
		ep->recv_task = NULL;
		if (ret != 0) {
			if (ret == -EABORT)
				wake_all_ep_writer(ep, -EIO);
			spin_unlock(&ep->lock);
			return ret;
		}

		if (!is_list_empty(&ep->pending_list)) {
			pending = list_first_entry(&ep->pending_list, struct kobject, list);
			list_del(&pending->list);
		} else {
			ep->recv_task = current;
			__event_task_wait((unsigned long)ep, TASK_EVENT_ENDPOINT, timeout);
		}

		if (pending != NULL)
			break;
		else
			spin_unlock(&ep->lock);

		ret = wait_event();
	}

	/*
	 * read the data from this task. if the task's data is wrong
	 * wake up this write task directly. otherwise mask this task
	 * as current pending task and waitting for endpoint_reply
	 */
	writer = (struct task *)pending->data;
	ret = kobject_copy_ipc_payload(current, writer,
			actual_data, actual_extra, 1, 0);
	if (ret < 0) {
		wake_up(writer, -EFAULT);
		ret = -EAGAIN;
		goto out;
	}

	list_add_tail(&ep->processing_list, &pending->list);
	ret = (long)writer->tid;

out:
	spin_unlock(&ep->lock);

	return ret;
}

static long endpoint_send(struct kobject *kobj, void __user *data, size_t data_size,
		void __user *extra, size_t extra_size, uint32_t timeout)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);
	struct poll_struct *ps = kobj->poll_struct;
	struct task *task;
	int ret;

	spin_lock(&ep->lock);
	if (ep->status[EP_READER] == EP_STAT_CLOSED) {
		spin_unlock(&ep->lock);
		return -EOTHERSIDECLOSED;
	}

	if (ep->status[EP_WRITER] == EP_STAT_CLOSED) {
		spin_unlock(&ep->lock);
		return -EIO;
	}

	/*
	 * setup the information which the task need wait
	 * for.
	 */
	list_add_tail(&ep->pending_list, &current->kobj.list);
	__event_task_wait((unsigned long)ep, TASK_EVENT_KOBJ_REPLY, timeout);
	spin_unlock(&ep->lock);

	/*
	 * if the releated kobject event is not polled, try
	 * to wake up the reading task.
	 */
	ret = poll_event_send(ps, EV_IN);
	if (ret == -EAGAIN) {
		spin_lock(&ep->lock);
		task = ep->recv_task;
		if (task)
			wake_up(task, 0);
		spin_unlock(&ep->lock);
	}

	ret = wait_event();
	if ((ret == 0) || (ret != -EABORT))
		return ret;

	/*
	 * the writer has been teminated, need delete this request
	 * from the pending list or processing list.
	 */
	spin_lock(&ep->lock);
	ASSERT(current->kobj.list.next != NULL);
	list_del(&current->kobj.list);
	spin_unlock(&ep->lock);

	return ret;
}

static int endpoint_reply(struct kobject *kobj, right_t right,
		long token, long errno, handle_t fd, right_t fd_right)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);
	struct kobject *wk, *tmp;
	struct task *task = NULL;

	/*
	 * find the task who are waitting the reply token, and wake
	 * up it with the error code.
	 */
	spin_lock(&ep->lock);

	list_for_each_entry_safe(wk, tmp, &ep->processing_list, list) {
		task = (struct task *)wk->data;
		if (task->tid == token) {
			list_del(&wk->list);
			break;
		}
	}

	if (task) {
		if (fd > 0) {
			errno = send_handle(current_proc, task->proc,
					fd, fd_right);
		}
		wake_up(task, errno);
	}

	spin_unlock(&ep->lock);

	if (!task)
		return -ENOENT;

	return 0;
}

static void endpoint_release(struct kobject *kobj)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);

	if (ep->shmem)
		free_pages(ep->shmem);

	free(ep);
}

static int endpoint_mmap(struct kobject *kobj, right_t right,
		void **addr, unsigned long *msize)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);
	unsigned long base;
	int ret;

	ASSERT(ep->shmem != NULL);
	base = va2sva(ep->shmem);

	ret = map_process_memory(current_proc, base, ep->shmem_size,
			vtop(ep->shmem), VM_RW | VM_SHARED);
	if (ret)
		return ret;

	*addr = (void *)base;
	*msize = ep->shmem_size;

	return 0;
}

static int endpoint_munmap(struct kobject *kobj, right_t right)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);
	unsigned long base;

	ASSERT(ep->shmem != NULL);
	base = va2sva(ep->shmem);

	return unmap_process_memory(current_proc, base, ep->shmem_size);
}

static struct kobject_ops endpoint_kobject_ops = {
	.send		= endpoint_send,
	.recv		= endpoint_recv,
	.release	= endpoint_release,
	.close		= endpoint_close,
	.mmap		= endpoint_mmap,
	.munmap		= endpoint_munmap,
	.reply		= endpoint_reply,
};

static int endpoint_create(struct kobject **kobj, right_t *right, unsigned long data)
{
	size_t shmem_size = data;
	struct endpoint *ep;
	right_t right_ep = EP_RIGHT;

	shmem_size = PAGE_BALIGN(shmem_size);
	if (shmem_size > HUGE_PAGE_SIZE)
		return -E2BIG;

	ep = zalloc(sizeof(struct endpoint));
	if (!ep)
		return -ENOMEM;

	if (shmem_size > 0) {
		ep->shmem = get_free_pages(shmem_size >> PAGE_SHIFT, GFP_USER);
		if (!ep->shmem) {
			free(ep);
			return -ENOMEM;
		}
		right_ep |= KOBJ_RIGHT_MMAP;
	}

	ep->shmem_size = shmem_size;
	init_list(&ep->pending_list);
	init_list(&ep->processing_list);
	kobject_init(&ep->kobj, KOBJ_TYPE_ENDPOINT, EP_RIGHT_MASK, (unsigned long)ep);
	ep->kobj.ops = &endpoint_kobject_ops;
	*kobj = &ep->kobj;
	*right = right_ep;

	return 0;
}
DEFINE_KOBJECT(endpoint, KOBJ_TYPE_ENDPOINT, endpoint_create);
