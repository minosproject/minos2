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

#define EP_READER		0
#define EP_WRITER		1
#define EP_NULL			2

#define EP_STAT_CLOSED		0
#define EP_STAT_OPENED		1

#define EP_NAME_SIZE		16
#define EP_RIGHT_MASK		(KOBJ_RIGHT_READ | KOBJ_RIGHT_WRITE | KOBJ_RIGHT_NONBLOCK)
#define EP_MAX_HANDLES		10
#define EP_MAX_HANDLES_SIZE	(EP_MAX_HANDLES * sizeof(handle_t))

#define EP_MODE_MUTIL_WRITER	1

struct endpoint {
	struct task *recv_task;			// which task is receiveing data from this endpoint.
	int status[2];				// status for the reader and writer.
	int mode;

	struct kobject kobj;			// kobj for this endpoint.
	atomic_t connected;

	spinlock_t lock;			// spinlock to prevent below member.
	struct list_head pending_list;		// pending write task will list here.
	struct list_head processing_list;	// the task which has aready processing and waiting reply.

	char name[EP_NAME_SIZE];		// the name of this endpoint.
};

struct endpoint_proto {
	unsigned long return_code;
	unsigned long data_addr;
	unsigned long data_size;
	unsigned long handle_addr;
	unsigned long handle_size;
	unsigned long flags;
	unsigned long timeout;
};

#define kobject_to_endpoint(kobj)	\
	(struct endpoint *)((kobj)->data)

#define task_endpoint_proto(task)	\
	(struct endpoint_proto *)task_syscall_regs(task)

#define EP_DIR(right)	\
	(right & KOBJ_RIGHT_READ) ? EP_READER : EP_WRITER

static int endpoint_open(struct kobject *kobj,
			handle_t handle, right_t right)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);

	ep->status[EP_DIR(right)] = EP_STAT_OPENED;

	return 0;
}

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

	if (ep->mode != EP_MODE_MUTIL_WRITER)
		ep->status[dir] = EP_STAT_CLOSED;

	if (dir == EP_READER) {
		spin_lock(&ep->lock);
		wake_all_ep_writer(ep, -EIO);
		spin_unlock(&ep->lock);
	}

	return 0;
}

static int endpoint_copy_handles(struct task *task, void __user *udst,
		void __user *usrc, size_t size)
{
	handle_t ksrc[EP_MAX_HANDLES];
	handle_t kdst[EP_MAX_HANDLES];
	struct kobject *kobjs[EP_MAX_HANDLES];
	struct kobject *kobj;
	right_t right;
	int ret, i;

	if (size == 0)
		return 0;

	ret = __copy_from_user(ksrc, &task->proc->vspace, usrc, size);
	if (ret)
		return -EFAULT;

	memset(kdst, 0, sizeof(kdst));

	for (i = 0; i < size / sizeof(handle_t); i++) {
		ret = get_kobject_from_process(task->proc, ksrc[i], &kobj, &right);
		if (ret)
			goto out;

		kobjs[i] = kobj;

		/*
		 * only the shared kobject can be passed to other process
		 * currently support SVMA (shared virtual memory area).
		 */
		if (!(kobj->right & KOBJ_RIGHT_SHARED))
			goto out;

		kdst[i] = alloc_handle(kobj, right);
		if (kdst[i] == HANDLE_NULL)
			goto out;
	}

	/*
	 * all done, copy the handles to the target process.
	 */
	ret = copy_to_user(udst, kdst, size);
	if (ret)
		goto out;

	return 0;
out:
	for (i = 0; i < size; i++) {
		if (kobjs[i] != NULL)
			kobject_put(kobjs[i]);
		if (kdst[i] == 0)
			break;
		release_handle(kdst[i]);
	}

	return -EMFILE;
}

static ssize_t endpoint_recv(struct kobject *kobj,
		void __user *data, size_t data_size,
		void __user *extra, size_t extra_size,
		uint32_t timeout)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);
	struct endpoint_proto *src;
	struct kobject *pending = NULL;
	struct task *writer;
	ssize_t ret = 0;

	for (;;) {
		spin_lock(&ep->lock);

		if ((ep->status[EP_READER] == EP_STAT_CLOSED) ||
			(ep->status[EP_WRITER] == EP_STAT_CLOSED)) {
			spin_unlock(&ep->lock);
			return -EIO;
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
			/*
			 * if the kobject has been listed by dedicated task, just
			 * return -EAGAIN, do not sleep to block other event to
			 * pass to the task. otherwise wait the event come.
			 */
			if ((kobj->poll_struct.poll_event & POLL_EV_TYPE_IN) || (timeout == 0)) {
				spin_unlock(&ep->lock);
				return -EAGAIN;
			} else {
				ep->recv_task = current;
				__event_task_wait((unsigned long)ep, TASK_EVENT_ENDPOINT, timeout);
			}
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
	src = task_endpoint_proto(writer);
	ASSERT(writer->wait_event == (unsigned long)ep);

	/*
	 * the endpoint size is not correct, or the handle cnt does
	 * not match, wake up the writer and pass the error code.
	 */
	if ((data_size != src->data_size) || (extra_size != src->handle_size) ||
			(extra_size > EP_MAX_HANDLES_SIZE)) {
		wake_up(writer, -EINVAL);
		ret = -EAGAIN;
		goto out;
	}

	/*
	 * copy the data from writer to the reader, then copy the
	 * handles from writer to the reader.
	 */
	ret = copy_user_to_user(&current->proc->vspace, data,
			&writer->proc->vspace,
			(void __user *)src->data_addr, data_size);
	if (ret <= 0) {
		wake_up(writer, -EFAULT);
		ret = -EAGAIN;
		goto out;
	}

	ret = endpoint_copy_handles(writer, extra,
			(void *)src->handle_addr, extra_size);
	if (ret) {
		wake_up(writer, -EFAULT);	
		ret = -EFAULT;
		goto out;
	}

	wake_up(writer, 0);
	list_add_tail(&ep->processing_list, &pending->list);
	ret = (long)writer->wait_event;

out:
	spin_unlock(&ep->lock);

	return ret;
}

static long generate_token(struct endpoint *ep)
{
	return 0;
}

static ssize_t endpoint_send(struct kobject *kobj,
		void __user *data, size_t data_size,
		void __user *extra, size_t extra_size,
		uint32_t timeout)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);
	struct poll_struct *ps = &kobj->poll_struct;
	struct task *task;
	int ret;

	spin_lock(&ep->lock);

	if ((ep->status[EP_READER] == EP_STAT_CLOSED) ||
			(ep->status[EP_WRITER] == EP_STAT_CLOSED)) {
		spin_unlock(&ep->lock);
		return -EIO;
	}

	/*
	 * setup the information which the task need wait
	 * for.
	 */
	list_add_tail(&ep->pending_list, &current->kobj.list);
	__event_task_wait(generate_token(ep), TASK_EVENT_KOBJ_REPLY, timeout);
	task = ep->recv_task;
	spin_unlock(&ep->lock);

	/*
	 * if there is some task waitting for the data, need to
	 * wake up this task.
	 */
	if (ps->poll_event & POLL_EV_IN)
		poll_event_send(ps->reader, POLL_EV_IN, ps->handle_reader);
	else if (task)
		wake_up(task, 0);

	ret = wait_event();
	if ((ret == 0) || (ret != -EABORT))
		return ret;

	/*
	 * the writer has been teminated, need delete this request
	 * from the pending list or processing list.
	 */
	spin_lock(&ep->lock);
	if (current->kobj.list.next != NULL)
		list_del(&current->kobj.list);
	spin_unlock(&ep->lock);

	return ret;
}

static int endpoint_reply(struct kobject *kobj,
		right_t right, long token, long errno)
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
		if (task->wait_event == token) {
			task = (struct task *)wk->data;
			list_del(&wk->list);
			break;
		}
	}

	if (task)
		wake_up(task, errno);

	spin_unlock(&ep->lock);

	if (!task)
		return -ENOENT;

	return 0;
}

static void endpoint_release(struct kobject *kobj)
{
	free(kobject_to_endpoint(kobj));
}

static int endpoint_connect(struct kobject *kobj, handle_t handle, right_t right)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);

	if (ep->mode != EP_MODE_MUTIL_WRITER) {
		if (atomic_cmpxchg(&ep->connected, 0, 1))
			return -EACCES;
	}

	return endpoint_open(kobj, handle, right);
}

static struct kobject_ops endpoint_kobject_ops = {
	.send		= endpoint_send,
	.recv		= endpoint_recv,
	.release	= endpoint_release,
	.connect	= endpoint_connect,
	.close		= endpoint_close,
	.reply		= endpoint_reply,
	.open		= endpoint_open,
};

static struct kobject *endpoint_create(char *str, right_t right,
		right_t right_req, unsigned long data)
{
	struct endpoint *ep;

	if ((data != 0) && (data != EP_MODE_MUTIL_WRITER))
		return ERROR_PTR(EPERM);

	/*
	 * the owner only can have read right or write right
	 * can not have both right.
	 */
	if ((right_req & KOBJ_RIGHT_RW) == KOBJ_RIGHT_RW)
		return ERROR_PTR(EPERM);

	ep = zalloc(sizeof(struct endpoint));
	if (!ep)
		return ERROR_PTR(ENOMEM);

	right &= EP_RIGHT_MASK;
	strcpy(ep->name, str);
	init_list(&ep->pending_list);
	init_list(&ep->processing_list);
	kobject_init(&ep->kobj, current_pid,
		KOBJ_TYPE_ENDPOINT, 0, right, (unsigned long)ep);
	ep->kobj.ops = &endpoint_kobject_ops;

	return &ep->kobj;
}
DEFINE_KOBJECT(endpoint, KOBJ_TYPE_ENDPOINT, endpoint_create);
