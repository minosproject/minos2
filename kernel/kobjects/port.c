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

#define PORT_NAME_SIZE	32

#define PORT_CAP_IN	0
#define PORT_CAP_OUT	1
#define PORT_CAP_PORT	2
#define PORT_CAP_CNT	3

extern int __kobject_connect(struct kobject *kobj, handle_t handle, right_t right);

struct port_create_arg {
	handle_t in;
	handle_t out;
	handle_t con;
};

static int port_client_rights[PORT_CAP_CNT] = {
	KOBJ_RIGHT_READ,
	KOBJ_RIGHT_WRITE,
	KOBJ_RIGHT_WRITE,
};

struct port {
	int right;
	struct kobject kobj;
	struct kobject *caps[PORT_CAP_CNT];
	char name[PORT_NAME_SIZE];
};

static int port_connect(struct kobject *kobj, handle_t handle, right_t right)
{
	struct port *port = (struct port *)kobj->data;
	struct kobject *kobjs[PORT_CAP_CNT];
	struct kobject *tmp;
	int i, ret;

	memset(kobjs, 0, sizeof(kobjs));

	for (i = 0; i < PORT_CAP_CNT; i++) {
		tmp = port->caps[0];
		if (!tmp)
			continue;

		ret = __kobject_connect(tmp, handle, port_client_rights[i]);
		if (ret)
			goto err_out;
		kobjs[i] = kobj;
	}

	return 0;

err_out:
	/*
	 * fallback if any kobject connected failed, the handle will
	 * released by connect_to_port.
	 */
	for (i = 0; i < PORT_CAP_CNT; i++) {
		tmp = kobjs[i];
		if (!tmp)
			continue;
		kobject_close(tmp, port_client_rights[i]);
	}

	return ret;
}

static int port_close(struct kobject *kobj, right_t right)
{
	return 0;
}

static ssize_t port_recv(struct kobject *kobj,
		void __user *data, size_t data_size,
		void __user *extra, size_t extra_size,
		uint32_t timeout)
{
	/*
	 * the port's owner can not call recv and send
	 * directly, it need control the specific kobject.
	 */
	struct port *port = (struct port *)kobj->data;
	struct kobject *kobj_read = port->caps[PORT_CAP_IN];

	if (current_pid == kobj->owner)
		return -EACCES;

	if (!kobj_read)
		return -EPERM;

	return kobject_recv(kobj_read, data, data_size, extra, extra_size, timeout);
}

static ssize_t port_send(struct kobject *kobj,
		void __user *data, size_t data_size,
		void __user *extra, size_t extra_size,
		uint32_t timeout)
{
	struct port *port = (struct port *)kobj->data;
	struct kobject *kobj_write = port->caps[PORT_CAP_OUT];

	/*
	 * the port's owner can not call recv and send
	 * directly, it need control the specific kobject.
	 */
	if (current_pid == kobj->owner)
		return -EACCES;

	if (!kobj_write)
		return -EPERM;

	return kobject_send(kobj_write, data, data_size, extra, extra_size, timeout);
}

static void port_release(struct kobject *kobj)
{

}

static struct kobject_ops port_kobject_ops = {
	.send		= port_send,
	.recv		= port_recv,
	.release	= port_release,
	.connect	= port_connect,
	.close		= port_close,
};

static struct kobject * __create_port(char *name, struct kobject *in,
		struct kobject *out, struct kobject *con, right_t right)
{
	struct port *port;

	port = zalloc(sizeof(struct port));
	if (!port)
		return NULL;

	port->caps[PORT_CAP_IN] = in;
	port->caps[PORT_CAP_OUT] = out;
	port->caps[PORT_CAP_PORT] = con;

	kobject_init(&port->kobj, current_pid, KOBJ_TYPE_PORT,
			0, right, (unsigned long)port);

	/*
	 * with the name, this kobject can be seen by
	 * other process.
	 */
	strncpy(port->name, name, PORT_NAME_SIZE - 1);
	port->kobj.right = right;
	port->kobj.name = port->name;
	port->kobj.ops = &port_kobject_ops;

	return &port->kobj;
}

static struct kobject *create_port(char *name, right_t r_req, int in, int out, int con)
{
	struct kobject *kin = NULL, *kout = NULL, *kcon = NULL;
	right_t right = 0, kright;
	int ret = 0;

	if (in != HANDLE_NULL) {
		ret = get_kobject(in, &kin, &kright);
		if (ret)
			return ERROR_PTR(-ENOENT);
		ret = kobject_check_right(kin, kright, KOBJ_RIGHT_READ);
		if (ret)
			return ERROR_PTR(-EPERM);
		right |= KOBJ_RIGHT_READ;
	}
	if (out != HANDLE_NULL) {
		ret = get_kobject(out, &kout, &kright);
		if (ret)
			return ERROR_PTR(-ENOENT);
		ret = kobject_check_right(kout, kright, KOBJ_RIGHT_WRITE);
		if (ret)
			return ERROR_PTR(-EPERM);
		right |= KOBJ_RIGHT_WRITE;
	}
	if (con != HANDLE_NULL) {
		ret = get_kobject(con, &kcon, &kright);
		if (!ret)
			return ERROR_PTR(-ENOENT);
		ret = kobject_check_right(kcon, kright, KOBJ_RIGHT_READ);
		if (ret)
			return ERROR_PTR(-EPERM);
		right |= KOBJ_RIGHT_READ;
	}

	if (right != r_req) {
		if (kin)
			put_kobject(kin);
		if (kout)
			put_kobject(kout);
		if (kout)
			put_kobject(kcon);
		return ERROR_PTR(-EPERM);
	}

	return __create_port(name, kin, kout, kcon, right);
}

static struct kobject *port_create(char *name, right_t right,
		right_t right_req, unsigned long data)
{
	struct port_create_arg args;
	int ret;

	ret = copy_from_user(&args, (void *)data, 
			sizeof(struct port_create_arg));
	if (ret < 0)
		return NULL;

	return create_port(name, right, args.in, args.out, args.con);
}
DEFINE_KOBJECT(port, KOBJ_TYPE_PORT, port_create);
