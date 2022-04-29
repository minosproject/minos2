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

#include "kobject_copy.h"

#define PORT_RIGHT 	KOBJ_RIGHT_RW
#define PORT_RIGHT_MASK KOBJ_RIGHT_WRITE

struct port {
	struct kobject kobj;
	struct iqueue iqueue;
};

#define kobject_to_port(kobj) (struct port *)((kobj)->data)

static int port_close(struct kobject *kobj, right_t right, struct process *proc)
{
	struct port *port = kobject_to_port(kobj);
	return iqueue_close(&port->iqueue, right, proc);
}

static long port_recv(struct kobject *kobj, void __user *data,
		size_t data_size, size_t *actual_data, void __user *extra,
		size_t extra_size, size_t *actual_extra, uint32_t timeout)
{
	struct port *port = kobject_to_port(kobj);
	return iqueue_recv(&port->iqueue, data, data_size, actual_data,
			extra, extra_size, actual_extra, timeout);
}

static long port_send(struct kobject *kobj, void __user *data, size_t data_size,
		void __user *extra, size_t extra_size, uint32_t timeout)
{
	struct port *port = kobject_to_port(kobj);
	return iqueue_send(&port->iqueue, data, data_size, extra, extra_size, timeout);
}

static int port_reply(struct kobject *kobj, right_t right,
		long token, long errno, handle_t fd, right_t fd_right)
{
	struct port *port = kobject_to_port(kobj);
	return iqueue_reply(&port->iqueue, right, token, errno, fd, fd_right);
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

static int port_create(struct kobject **kobj, right_t *right, unsigned long data)
{
	struct port *port;

	port = zalloc(sizeof(struct port));
	if (!port)
		return -ENOMEM;

	iqueue_init(&port->iqueue, 1, &port->kobj);
	kobject_init(&port->kobj, KOBJ_TYPE_PORT, PORT_RIGHT_MASK, (unsigned long)port);
	port->kobj.ops = &port_kobject_ops;
	*kobj = &port->kobj;
	*right = PORT_RIGHT;

	return 0;
}
DEFINE_KOBJECT(port, KOBJ_TYPE_PORT, port_create);
