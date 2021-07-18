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
#include <minos/endpoint.h>
#include <minos/uaccess.h>
#include <minos/mm.h>
#include <minos/sched.h>

#define kobject_to_endpoint(kobj)	\
	(struct endpoint *)((kobj)->data)

#define task_endpoint_proto(task)	\
	(struct endpoint_proto *)task_syscall_regs(task)

static int endpoint_open(struct kobject *kobj, handle_t handle, right_t right)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);
	int dir;

	/*
	 * one process can not have both RW right for an endpoint 
	 */
	switch (right & KOBJ_RIGHT_RW) {
	case KOBJ_RIGHT_READ:
		dir = EP_READER;
		break;
	case KOBJ_RIGHT_WRITE:
		dir = EP_WRITER;
		break;
	default:
		return -EPERM;
	}

	spin_lock(&ep->lock);

	/*
	 * the endpoint has already been opened
	 */
	if (ep->handles[dir]) {
		spin_unlock(&ep->lock);
		return -EACCES;
	}

	ep->owner[dir] = current->proc->pid;
	ep->handles[dir] = handle;
	ep->status[dir] = EP_STAT_OPENED;
	spin_unlock(&ep->lock);

	return 0;
}

static int endpoint_close(struct kobject *kobj, right_t right)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);
	int dir;

	switch (right & KOBJ_RIGHT_RW) {
	case KOBJ_RIGHT_READ:
		dir = EP_READER;
		break;
	case KOBJ_RIGHT_WRITE:
		dir = EP_WRITER;
		break;
	default:
		return -EPERM;
	}

	spin_lock(&ep->lock);
	ep->owner[dir] = 0;
	ep->handles[dir] = HANDLE_NULL;
	ep->status[dir] = EP_STAT_CLOSED;
	spin_unlock(&ep->lock);

	return 0;
}

static int endpoint_copy_handles(struct task *task, void __user *udst, void __user *usrc, size_t size)
{
	handle_t ksrc[EP_MAX_HANDLES];
	handle_t kdst[EP_MAX_HANDLES];
	struct kobject *kobjs[EP_MAX_HANDLES];
	struct kobject *kobj;
	right_t right;
	int ret, i;

	ret = __copy_from_user(ksrc, &task->proc->vspace, usrc, size);
	if (ret)
		return ret;

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
	long ret = 0;

	while (1) {
		spin_lock(&ep->lock);

		if (ep->status[EP_WRITER] == EP_STAT_CLOSED) {
			spin_unlock(&ep->lock);
			return -EIO;
		}

		/*
		 * only one task can wait for data on the endpoint, if
		 * there is already reading task, return -EBUSY.
		 * if wait_event fail, then return error, before return
		 * need set the recv_task to NULL.
		 */
		if (ep->recv_task && (ep->recv_task != current)) {
			spin_unlock(&ep->lock);
			return -EBUSY;
		}

		ep->recv_task = NULL;
		if (ret) {
			spin_unlock(&ep->lock);
			return ret;
		}

		if (!is_list_empty(&ep->pending_list)) {
			pending = list_first_entry(&ep->pending_list, struct kobject, list);
			list_del(&pending->list);
		} else {
			/*
			 * if the kobject has been binded to dedicated task, just
			 * return -EAGAIN, do not sleep to block other event to
			 * pass to the task. otherwise wait the event come.
			 */
			if (kobj->poll_struct.poll_event & POLL_READER_BIT) {
				spin_unlock(&ep->lock);
				return -EAGAIN;
			} else {
				ep->recv_task = current;
				__event_task_wait((unsigned long)ep, TASK_EVENT_ENDPOINT, timeout);
			}
		}
		spin_unlock(&ep->lock);

		if (pending != NULL)
			break;

		ret = wait_event();
	}

	/*
	 * read the data from this task. if the task's data is wrong
	 * wake up this write task directly. otherwise mask this task
	 * as current pending task and waitting for endpoint_reply
	 */
	writer = (struct task *)pending->data;
	src = task_endpoint_proto(writer);

	ASSERT(writer->wait_event != (unsigned long)ep);

	/*
	 * the endpoint size is not correct, or the handle cnt does
	 * not match, wake up the writer and pass the error code.
	 */
	if ((data_size != src->data_size) || (extra_size != src->handle_size) ||
			(extra_size > EP_MAX_HANDLES_SIZE)) {
		wake_up(writer, -EINVAL);
		return -EAGAIN;
	}

	/*
	 * copy the data from writer to the reader, then copy the
	 * handles from writer to the reader.
	 */
	if (copy_user_to_user(&current->proc->vspace, data, &writer->proc->vspace,
				(void __user *)src->data_addr, data_size)) {
		wake_up(writer, -EFAULT);
		return -EAGAIN;
	}

	if (endpoint_copy_handles(writer, extra, (void __user *)src->handle_addr, extra_size)) {	
		wake_up(writer, -EFAULT);	
		return -EAGAIN;
	}

	/*
	 * every thing is down, return to the reader, and add
	 * the waiter to the process list. will return the
	 * transaction id to the reader, so the reader can
	 * reply to the writer. wakeup the writer.
	 */
	if (kobj->flags & KOBJ_FLAGS_NEED_REPLY) {
		spin_lock(&ep->lock);
		list_add_tail(&ep->processing_list, &pending->list);
		spin_unlock(&ep->lock);
	} else {
		wake_up(writer, 0);
	}

	return (long)writer->wait_event;
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
	struct task *task = current;
	struct poll_struct *ps = &kobj->poll_struct;
	int ret;

	spin_lock(&ep->lock);

	if (ep->status[EP_READER] == EP_STAT_CLOSED) {
		spin_unlock(&ep->lock);
		return -EIO;
	}

	list_add_tail(&ep->pending_list, &current->kobj.list);

	/*
	 * setup the information which the task need wait
	 * for.
	 */
	__event_task_wait(generate_token(ep), TASK_EVENT_KOBJ_REPLY, timeout);

	task = ep->recv_task;
	spin_unlock(&ep->lock);

	/*
	 * if there is some task waitting for the data, need to
	 * wake up this task.
	 */
	if (ps->poll_event & POLL_EV_IN)
		poll_event_send(ps->tid_reader, POLL_EV_IN, ps->handle_reader);
	else if (task)
		wake_up(task, 0);

	ret = wait_event();
	if (ret == 0)
		return 0;

	/*
	 * something wrong, need delete this request from the pending
	 * list.
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
	struct kobject *wk, *tmp;
	struct task *task = NULL;
	struct endpoint *ep;

	if (!(kobj->flags & KOBJ_FLAGS_NEED_REPLY))
		return 0;

	/*
	 * find the task who are waitting the reply token, and wake
	 * up it with the error code.
	 */
	ep = kobject_to_endpoint(kobj);
	spin_lock(&ep->lock);

	list_for_each_entry_safe(wk, tmp, &ep->processing_list, list) {
		if (task->wait_event == token) {
			task = (struct task *)wk->data;
			list_del(&wk->list);
			break;
		}
	}

	spin_unlock(&ep->lock);
	if (!task)
		return -ENOENT;

	wake_up(task, errno);

	return 0;
}

static void endpoint_release(struct kobject *kobj)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);
	free(ep);
}

static int endpoint_connect(struct kobject *kobj, handle_t handle, right_t right)
{
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
