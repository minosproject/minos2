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

#define PORT_RIGHT (KOBJ_RIGHT_RW | KOBJ_RIGHT_GRANT)

struct port {
	struct task *recv_task;
	int closed;
	uint32_t token;
	struct kobject kobj;
	spinlock_t lock;
	struct list_head pending_list;
	struct list_head processing_list;
};

#define kobject_to_port(kobj) (struct port *)((kobj)->data)

static void wake_all_port_writer(struct port *port, int errno)
{
	struct kobject *kobj, *tmp;

	list_for_each_entry_safe(kobj, tmp, &port->pending_list, list) {
		wake_up((struct task *)kobj->data, errno);
		list_del(&kobj->list);
	}

	list_for_each_entry_safe(kobj, tmp, &port->processing_list, list) {
		wake_up((struct task *)kobj->data, errno);
		list_del(&kobj->list);
	}
}

static int port_close(struct kobject *kobj, right_t right)
{
	struct port *port = kobject_to_port(kobj);

	if (right & KOBJ_RIGHT_WRITE)
		return 0;

	port->closed = 1;
	smp_wmb();

	spin_lock(&port->lock);
	wake_all_port_writer(port, -EOTHERSIDECLOSED);
	spin_unlock(&port->lock);

	return 0;
}

static long port_recv(struct kobject *kobj, void __user *data,
		size_t data_size, size_t *actual_data, void __user *extra,
		size_t extra_size, size_t *actual_extra, uint32_t timeout)
{
	struct port *port = kobject_to_port(kobj);
	struct kobject *pending = NULL;
	struct task *writer;
	ssize_t ret = 0;

	for (;;) {
		spin_lock(&port->lock);

		if (port->closed) {
			spin_unlock(&port->lock);
			return -EIO;
		}

		/*
		 * only one task can wait for data on the port, if
		 * there is already reading task, return -EBUSY.
		 * if wait_event fail, then return error, before return
		 * need set the recv_task to NULL.
		 */
		if ((port->recv_task != NULL) && (port->recv_task != current)) {
			spin_unlock(&port->lock);
			return -EBUSY;
		}

		/*
		 * clear the recv_task in port, later this value will
		 * be set again if need sleport.
		 */
		port->recv_task = NULL;
		if (ret != 0) {
			if (ret == -EABORT)
				wake_all_port_writer(port, -EIO);
			spin_unlock(&port->lock);
			return ret;
		}

		if (!is_list_empty(&port->pending_list)) {
			pending = list_first_entry(&port->pending_list, struct kobject, list);
			list_del(&pending->list);
		} else {
			port->recv_task = current;
			__event_task_wait((unsigned long)port, TASK_EVENT_ENDPOINT, timeout);
		}

		if (pending != NULL)
			break;
		else
			spin_unlock(&port->lock);

		ret = wait_event();
	}

	/*
	 * read the data from this task. if the task's data is wrong
	 * wake up this write task directly. otherwise mask this task
	 * as current pending task and waitting for port_rportly
	 */
	writer = (struct task *)pending->data;
	ret = kobject_copy_ipc_payload(current, writer,
			actual_data, actual_extra, 1, 0);
	if (ret < 0) {
		wake_up(writer, -EFAULT);
		ret = -EAGAIN;
		goto out;
	}

	list_add_tail(&port->processing_list, &pending->list);
	ret = (long)writer->wait_event;

out:
	spin_unlock(&port->lock);

	return ret;
}

static inline long port_generate_token(struct port *port)
{
	uint32_t token = port->token++;

	return (long)token;
}

static long port_send(struct kobject *kobj, void __user *data, size_t data_size,
		void __user *extra, size_t extra_size, uint32_t timeout)
{
	struct port *port = kobject_to_port(kobj);
	struct poll_struct *ps = kobj->poll_struct;
	struct task *task;
	int ret;

	spin_lock(&port->lock);

	if (port->closed) {
		spin_unlock(&port->lock);
		return -EOTHERSIDECLOSED;
	}

	/*
	 * setup the information which the task need waitting
	 * for.
	 */
	list_add_tail(&port->pending_list, &current->kobj.list);
	__event_task_wait(port_generate_token(port),
			TASK_EVENT_KOBJ_REPLY, timeout);
	task = port->recv_task;
	spin_unlock(&port->lock);

	/*
	 * if the releated kobject event is not polled, try
	 * to wake up the reading task.
	 */
	ret = poll_event_send(ps, EV_IN);
	if (ret == -EAGAIN) {
		spin_lock(&port->lock);
		task = port->recv_task;
		if (task)
			wake_up(task, 0);
		spin_unlock(&port->lock);
	}

	ret = wait_event();
	if ((ret == 0) || (ret != -EABORT))
		return ret;

	/*
	 * the writer has been teminated, need delete this request
	 * from the pending list or processing list.
	 */
	spin_lock(&port->lock);
	ASSERT(current->kobj.list.next != NULL);
	list_del(&current->kobj.list);
	spin_unlock(&port->lock);

	return ret;
}

static int port_reply(struct kobject *kobj, right_t right,
		long token, long errno, handle_t fd, right_t fd_right)
{
	struct port *port = kobject_to_port(kobj);
	struct kobject *wk, *tmp;
	struct task *task = NULL;

	/*
	 * find the task who are waitting the rportly token, and wake
	 * up it with the error code.
	 */
	spin_lock(&port->lock);

	list_for_each_entry_safe(wk, tmp, &port->processing_list, list) {
		task = (struct task *)wk->data;
		if (task->wait_event == token) {
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

	spin_unlock(&port->lock);

	if (!task)
		return -ENOENT;

	return 0;
}

static void port_release(struct kobject *kobj)
{
	free(kobject_to_port(kobj));
}

static int port_poll(struct kobject *ksrc,
		struct kobject *kdst, int event, bool enable)
{
	return ((event == EV_WOPEN) || event == EV_WCLOSE ? -EINVAL : 0);
}

static struct kobject_ops port_kobject_ops = {
	.send		= port_send,
	.recv		= port_recv,
	.release	= port_release,
	.close		= port_close,
	.reply		= port_reply,
	.poll		= port_poll,
};

static struct kobject *port_create(right_t right,
		right_t right_req, unsigned long data)
{
	struct port *port;

	if ((right & ~PORT_RIGHT) || (right_req & ~PORT_RIGHT))
		return ERROR_PTR(-EPERM);

	/*
	 * the owner only can have read right or write right
	 * can not have both right.
	 */
	if ((right_req & KOBJ_RIGHT_RW) == KOBJ_RIGHT_RW)
		return ERROR_PTR(-EPERM);

	port = zalloc(sizeof(struct port));
	if (!port)
		return ERROR_PTR(-ENOMEM);

	init_list(&port->pending_list);
	init_list(&port->processing_list);
	kobject_init(&port->kobj, KOBJ_TYPE_PORT, right, (unsigned long)port);
	port->kobj.ops = &port_kobject_ops;

	return &port->kobj;
}
DEFINE_KOBJECT(port, KOBJ_TYPE_PORT, port_create);
