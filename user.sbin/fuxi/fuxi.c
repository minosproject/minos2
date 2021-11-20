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

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/dir.h>
#include <sys/epoll.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#include <minos/list.h>
#include <minos/proto.h>
#include <minos/kobject.h>
#include <minos/debug.h>
#include <minos/types.h>
#include <minos/service.h>
#include <misc.h>

#define VNODENAME_MAX 64
#define VNODE_MAX 128
#define VREQ_MAX 256
#define MAX_EVENTS 10

struct vnode {
	int type;
	int open_cnt;
	int handle;			// for service node.
	int d_ino;
	char name[VNODENAME_MAX];
	struct list_head child;
	struct list_head list;
};

struct vreq {
	int handle;			// for ipc between two process.
	int right;
	struct vnode *node;
	struct vreq *next;
	struct list_head *pdata;
	void *buf;
};

static struct vnode vnodes[VNODE_MAX];
static LIST_HEAD(node_list);

static struct vreq vreqs[VREQ_MAX];
static struct vreq *vreq_head = NULL;

static struct vnode root_vnode;
static int epfd;

static char string_buffer[PATH_MAX];
static char filename[PATH_MAX];

static void fuxi_info(char *str)
{
	kobject_write(2, str, strlen(str), NULL, 0, 0);
}

static struct vreq *alloc_vreq(void)
{
	struct vreq *vreq;

	if (vreq_head == NULL)
		return NULL;

	vreq = vreq_head;
	vreq_head = vreq->next;
	vreq->next = NULL;

	return vreq;
}

static void release_vreq(struct vreq *vreq)
{
	vreq->next = vreq_head;
	vreq_head = vreq;
}

static void vreqs_init(void)
{
	struct vreq *vreq;
	int i;

	for (i = 0; i < VREQ_MAX; i++) {
		vreq = &vreqs[i];
		vreq->next = vreq_head;
		vreq_head = vreq;
	}
}

static int epoll_new_vreq(struct vreq *vreq)
{
	struct epoll_event event;

	event.events = EPOLLIN;
	event.data.ptr = vreq;

	return epoll_ctl(epfd, EPOLL_CTL_ADD, vreq->handle, &event);
}

static struct vnode *alloc_node(void)
{
	struct vnode *node;

	if (is_list_empty(&node_list))
		return NULL;

	node = list_first_entry(&node_list, struct vnode, list);
	list_del(&node->list);

	return node;
}

static void release_node(struct vnode *node)
{
	list_del(&node->list);
	list_add(&node_list, &node->list);
}

static int handle_close_event(struct epoll_event *event)
{
	struct vreq *vreq = (struct vreq *)event->data.ptr;
	struct vnode *node = vreq->node;

	if (node->handle)
		kobject_close(node->handle);

	release_node(node);
	release_vreq(vreq);

	return 0;
}

static struct vreq *create_new_vreq(struct vnode *node)
{
	struct vreq *vreq;
	int ret;

	vreq = alloc_vreq();
	if (!vreq)
		return NULL;

	/*
	 * create a normal endpoint which allow two process
	 * to IPC with each other.
	 */
	vreq->handle = kobject_create_endpoint(PAGE_SIZE);
	if (vreq->handle <= 0)
		goto err_create_endpoint;

	if (kobject_mmap(vreq->handle, &vreq->buf, NULL))
		goto err_open_endpoint;

	ret = epoll_new_vreq(vreq);
	if (ret)
		goto err_open_endpoint;

	/*
	 * pointed to the first member in the node.
	 */
	vreq->node = node;
	vreq->pdata = node->child.next;

	return vreq;

err_open_endpoint:
	kobject_close(vreq->handle);
err_create_endpoint:
	release_vreq(vreq);
	return NULL;
}

static int open_remote_node(struct vnode *node,
			struct proto *proto, char *name)
{
	return kobject_write(node->handle, proto,
			sizeof(struct proto), name, strlen(name), 5000);
}

static struct vnode *find_node(struct vnode *parent, char *name)
{
	struct vnode *node;

	list_for_each_entry(node, &parent->child, list) {
		if (strcmp(name, node->name) == 0)
			return node;
	}

	return NULL;
}

static int check_string(char *buf, int offset, int size)
{
	while (offset < size) {
		if (buf[offset] == '\0')
			return 1;
		offset++;
	}

	return 0;
}

static struct vnode *find_dir_node(struct vnode *root, char *buf)
{
	struct vnode *cur = root;
	char *pathrem = buf, *end;

	for (;;) {
		while (*pathrem == '/')
			pathrem++;

		if (cur->type != SRV_DIR)
			break;

		/*
		 * open a directory of the SNS, SNS only provide two file type
		 * one is directory, other is service.
		 */
		if (*pathrem == '\0')
			return cur;

		end = strchrnul(pathrem, '/');
		if (end - pathrem >= PATH_MAX)
			break;

		strlcpy(filename, pathrem, end - pathrem + 1);
		pathrem = end;

		cur = find_node(cur, filename);
		if (!cur)
			break;
	}

	return NULL;
}

static int create_service_kobject(struct vnode *node, struct proto *proto)
{
	int handle;

	switch (proto->register_service.type) {
	case SRV_PORT:
		handle = kobject_create_port();
		break;
	case SRV_NOTIFY:
		handle = kobject_create_notify();
		break;
	default:
		handle = -1;
		break;
	}

	if (handle <= 0)
		return handle;

	node->handle = handle;
	node->open_cnt = 0;

	return 0;
}

static struct vnode *__handle_register_service_request(struct vreq *vreq,
		struct proto *proto, char *buf)
{
	char *source = buf + proto->register_service.source_off;
	char *target = buf + proto->register_service.target_off;
	struct vnode *parent = vreq->node;
	struct vnode *node;

	if (parent->d_ino != -1)
		return NULL;

	if (!check_string(buf, proto->register_service.source_off, PATH_MAX))
		return NULL;

	if (!check_string(buf, proto->register_service.target_off, PATH_MAX))
		return NULL;

	if (strlen(target) >= VNODENAME_MAX)
		return NULL;

	parent = find_dir_node(parent, source);
	if (!parent)
		return NULL;

	node = alloc_node();
	if (!node)
		return NULL;

	strcpy(node->name, target);
	node->type = proto->register_service.type;

	if (node->type == SRV_DIR) {
		node->handle = -1;
		init_list(&node->child);
		list_add_tail(&parent->child, &node->list);
	} else {
		if (create_service_kobject(node, proto)) {
			release_node(node);
			node = NULL;
		} else {
			list_add_tail(&parent->child, &node->list);
		}
	}

	return node;
}

static void handle_register_service_request(struct vreq *vreq, struct proto *proto, char *buf)
{
	struct vnode *node;

	node = __handle_register_service_request(vreq, proto, buf);
	if (!node) {
		kobject_reply_errcode(vreq->handle, proto->token, -EINVAL);
		return;
	}

	switch (node->type) {
	case SRV_PORT:
		kobject_reply_handle(vreq->handle, proto->token, node->handle, KR_R);
		break;
	case SRV_NOTIFY:
		kobject_reply_handle(vreq->handle, proto->token, node->handle, KR_W);
		break;
	default:
		kobject_reply_errcode(vreq->handle, proto->token, -EINVAL);
		break;
	}
}

static int __handle_open_request(struct vreq *vreq, struct proto *proto, char *buf, int *type)
{
	struct vnode *cur = vreq->node, *next;
	struct vreq *new_vreq;
	char *pathrem = buf, *end;
	int handle = -EINVAL;

	for (;;) {
		while (*pathrem == '/')
			pathrem++;

		/*
		 * open a directory of the SNS, SNS only provide two file type
		 * one is directory, other is service.
		 */
		if (*pathrem == '\0') {
			if (cur->type == SRV_NOTIFY) {
				if (!(proto->open.flags & O_DIRECTORY)) {
					*type = SRV_NOTIFY;
					return cur->handle;
				} else {
					return -ENOENT;
				}
			}

			if (!(proto->open.flags & O_DIRECTORY) && (cur->type != SRV_DIR))
				return -ENOENT;

			/*
			 * open a directly, create a new endpoint for the request.
			 */
			new_vreq = create_new_vreq(cur);
			if (new_vreq != NULL) {
				*type = SRV_DIR;
				handle = new_vreq->handle;
			}

			return handle;
		}

		if (cur->type != SRV_DIR)
			return -ENOENT;

		end = strchrnul(pathrem, '/');
		if (end - pathrem >= PATH_MAX)
			return -ENAMETOOLONG;

		strlcpy(filename, pathrem, end - pathrem + 1);
		pathrem = end;

		next = find_node(cur, filename);
		if (!next)
			return -ENOENT;

		/*
		 * if this node is a service node, open it with remote call.
		 */
		if ((next->type == SRV_PORT)) {
			*type = SRV_REMOTE;
			return open_remote_node(next, proto, pathrem);
		}
	}

	return -ENOENT;
}

static void handle_open_request(struct vreq *vreq, struct proto *proto, char *buf)
{
	int type = 0;
	int handle;
	int right;

	handle = __handle_open_request(vreq, proto, buf, &type);
	if (handle <= 0) {
		right = 0;
		fuxi_info("open file failed\n");
	} else {
		if (type == SRV_DIR)
			right = KR_WM;
		else if (type == SRV_PORT)
			right = KR_W;
		else if (type == SRV_NOTIFY)
			right = KR_R;
		else
			right = 0;
	}

	/*
	 * close the handle if this handle is a remote handle. the
	 * rights has been passed to the target process.
	 */
	kobject_reply_handle(vreq->handle, proto->token, handle, right);
	if (handle > 0 && type == SRV_REMOTE)
		kobject_close(handle);
}

static void handle_getdent_request(struct vreq *vreq, struct proto *proto, char *buf)
{
	struct vnode *node = vreq->node;
	unsigned char *tmp = vreq->buf;
	struct dirent *de;
	int ret = 0, len;
	struct vnode *next;
	int size_left = PAGE_SIZE;

	if (node->type != SRV_DIR) {
		ret = -EBADF;
		goto out;
	}

	if (vreq->pdata == NULL) {
		ret = -EPERM;
		goto out;
	}

	for (;;) {
		if (vreq->pdata == &vreq->node->child)
			break;

		next = list_entry(vreq->pdata, struct vnode, list);
		if (next == NULL)
			break;

		len = DIRENT_SIZE(strlen(next->name) + 1);
		if (size_left < len)
			break;

		de = (struct dirent *)tmp;
		de->d_ino = node->d_ino;
		de->d_off = node->d_ino;
		de->d_reclen = len;
		de->d_type = DT_SRV;
		strcpy(de->d_name, next->name);

		tmp += len;
		size_left -= len;
		vreq->pdata = vreq->pdata->next;
	}

	ret = PAGE_SIZE - size_left;
out:
	kobject_reply(vreq->handle, proto->token, ret, 0, 0);
}

static int handle_remote_access(struct vnode *node, struct proto *proto, char *buf)
{
	struct proto rproto;

	rproto.proto_id = PROTO_ACCESS;
	rproto.access.amode = proto->access.amode;

	return sys_send_proto_with_data(node->handle,
			&rproto, buf, strlen(buf), 2000);
}

static int __handle_access_request(struct vreq *vreq, struct proto *proto, char *buf)
{
	struct vnode *cur = vreq->node, *next;
	int amode = proto->access.amode;
	char *pathrem = buf, *end;

	for (;;) {
		while (*pathrem == '/')
			pathrem++;

		/*
		 * open a directory of the fuxi, fuxi only provide two file type
		 * one is directory, other is service.
		 */
		if (*pathrem == '\0') {
			if (cur->type == SRV_NOTIFY)
				return ((amode & R_OK) == amode);
			else if (cur->type == SRV_PORT)
				return ((amode & W_OK) == amode);
			else
				return -EPERM;
		}

		if (cur->type != SRV_DIR)
			return -ENOENT;

		end = strchrnul(pathrem, '/');
		if (end - pathrem >= PATH_MAX)
			return -ENAMETOOLONG;

		strlcpy(filename, pathrem, end - pathrem + 1);
		pathrem = end;

		next = find_node(cur, filename);
		if (!next)
			return -ENOENT;

		/*
		 * if this node is a service node, open it with remote call.
		 */
		if ((next->type == SRV_PORT))
			return handle_remote_access(next, proto, pathrem);
	}

	return -ENOENT;
}

static void handle_access_request(struct vreq *vreq,
		struct proto *proto, char *path)
{
	int ret = __handle_access_request(vreq, proto, path);
	kobject_reply_errcode(vreq->handle, proto->token, ret);
}

static void handle_lseek_request(struct vreq *vreq,
		struct proto *proto, char *sbuf)
{
	struct vnode *node = vreq->node;
	int ret = -EPERM;

	/*
	 * TBD
	 */
	if (node->type == SRV_DIR) {
		vreq->pdata = node->child.next;
		ret = 0;
	}

	kobject_reply_errcode(vreq->handle, proto->token, ret);
}

static int handle_event(struct epoll_event *event)
{
	struct vreq *vreq = (struct vreq *)event->data.ptr;
	struct proto proto;
	int ret;

	ret = sys_read_proto_with_string(vreq->handle, &proto,
			string_buffer, PATH_MAX, 0);
	if (ret)
		return ret;

	if ((vreq->buf == NULL) && (proto.proto_id == PROTO_GETDENTS)) {
		kobject_reply_errcode(vreq->handle, proto.token, -EPERM);
		return -EPERM;
	}

	switch (proto.proto_id) {
	case PROTO_OPEN:
		handle_open_request(vreq, &proto, string_buffer);
		break;
	case PROTO_ACCESS:
		handle_access_request(vreq, &proto, string_buffer);
		break;
	case PROTO_GETDENTS:
		handle_getdent_request(vreq, &proto, string_buffer);
		break;
	case PROTO_REGISTER_SERVICE:
		handle_register_service_request(vreq, &proto, string_buffer);
		break;
	case PROTO_LSEEK:
		handle_lseek_request(vreq, &proto, string_buffer);
		break;
	case PROTO_READ:
	case PROTO_WRITE:
	case PROTO_IOCTL:
	default:
		kobject_reply_errcode(vreq->handle, proto.token, -EPERM);
		break;
	};

	return ret;
}

static int fuxi_loop(int handle)
{
	struct epoll_event events[MAX_EVENTS];
	struct epoll_event *event = &events[0];
	struct vreq *vreq;
	int ret, i;

	epfd = epoll_create(MAX_EVENTS);
	if (epfd <= 0)
		exit(-ENOSPC);

	vreq = alloc_vreq();
	vreq->handle = handle;
	vreq->node = &root_vnode;
	vreq->pdata = NULL;
	vreq->buf = NULL;

	event->data.ptr = vreq;
	event->events = EPOLLIN;
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, vreq->handle, event);
	if (ret)
		exit(ret);

	/*
	 * inform the root service, that we are ok.
	 */
	i_am_ok();

	fuxi_info("fuxi: waitting request\n");

	for (;;) {
		ret = epoll_wait(epfd, events, MAX_EVENTS, -1);
		if (ret <= 0) {
			fuxi_info("vfs epoll failed\n");
			continue;
		}

		// fuxi_info("fuxi: receive service request\n");

		for (i = 0; i < ret; i++) {
			switch (events[i].events) {
			case EPOLLIN:
				handle_event(&events[i]);
				break;
			case EPOLLWCLOSE:
				handle_close_event(&events[i]);
				break;
			default:
				break;
			}
		}
	}

	return -1;
}

static void root_vnode_init(void)
{
	strcpy(root_vnode.name, "/");
	root_vnode.type = SRV_DIR;
	root_vnode.d_ino = -1;
	init_list(&root_vnode.child);
}

static void vnodes_init(void)
{
	int i;

	memset(vnodes, 0, VNODE_MAX * sizeof(struct vnode));
	for (i = 0; i < VNODE_MAX; i++) {
		vnodes[i].d_ino = i;
		list_add_tail(&node_list, &vnodes[i].list);
	}

	root_vnode_init();
}

/*
 * 0 - root service
 * 1 - stdin
 * 2 - stdout
 * 3 - stderr
 */
int main(int argc, char **argv)
{
	int handle;

	fuxi_info("\n\nFuXi service start...\n\n");

	if (get_handles(argc, argv, &handle, 1) != 1) {
		pr_err("get fuxi handle fail\n");
		return -ENOENT;
	}

	pr_info("fuxi handle %d\n", handle);

	vnodes_init();
	vreqs_init();

	exit(fuxi_loop(handle));
}
