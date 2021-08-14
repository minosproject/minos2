/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/dir.h>
#include <sys/epoll.h>
#include <errno.h>
#include <string.h>
#include <sys/mount.h>

#include <minos/list.h>
#include <minos/proto.h>
#include <minos/kobject.h>
#include <minos/debug.h>
#include <minos/types.h>

#define VNODENAME_MAX 64
#define VNODE_MAX 128
#define VREQ_MAX 256
#define MAX_EVENTS 10

struct vnode {
	int type;
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

static char string_buffer[FILENAME_MAX];
static char filename[FILENAME_MAX];

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

	return epoll_ctl(EPOLL_CTL_ADD, epfd, vreq->handle, &event);
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

static int handle_kernel_event(struct epoll_event *event)
{
	struct vreq *vreq = (struct vreq *)event->data.ptr;
	struct vnode *node = vreq->node;

	switch (event->data.type) {
	case POLLIN_KOBJ_CLOSE:
		if (node->handle > 0)
			kobject_close(node->handle);
		release_node(node);
		release_vreq(vreq);
		break;
	default:
		break;
	}

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
	vreq->handle = kobject_create_endpoint(KR_RWCMG, KR_RCMG, PAGE_SIZE);
	if (vreq->handle <= 0)
		goto err_create_endpoint;

	ret = kobject_open(vreq->handle);
	if (ret)
		goto err_open_endpoint;

	vreq->buf = kobject_mmap(vreq->handle);
	if (vreq->buf == (void *)-1)
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
			sizeof(struct proto), name, strlen(name), -1);
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

		if (cur->type != DT_DIR)
			break;

		/*
		 * open a directory of the SNS, SNS only provide two file type
		 * one is directory, other is service.
		 */
		if (*pathrem == '\0')
			return cur;

		end = strchrnul(pathrem, '/');
		if (end - pathrem >= FILENAME_MAX)
			break;

		strlcpy(filename, pathrem, end - pathrem + 1);
		pathrem = end;

		cur = find_node(cur, filename);
		if (!cur)
			break;
	}

	return NULL;
}

static int __handle_unmount_request(struct vreq *vreq, struct proto *proto, char *buf)
{
	struct vnode *parent = vreq->node;
	struct vnode *node;
	char *source = buf + proto->mount.source_off;
	char *target = buf + proto->mount.target_off;
	int ret = 0;

	if (parent->d_ino != -1)
		return -EPERM;

	if (!check_string(buf, proto->mount.source_off, FILENAME_MAX))
		return -EINVAL;

	if (!check_string(buf, proto->mount.target_off, FILENAME_MAX))
		return -EINVAL;

	parent = find_dir_node(parent, source);
	if (!parent)
		return -ENOENT;

	node = find_node(parent, target);
	if (!node)
		return -ENOENT;

	if (!is_list_empty(&node->child))
		return -ENOTEMPTY;

	list_del(&node->list);
	if (node->handle > 0)
		kobject_close(node->handle);

	node->handle = -1;
	node->type = 0;

	return ret;
}

static void handle_unmount_request(struct vreq *vreq, struct proto *proto, char *buf)
{
	int ret = __handle_unmount_request(vreq, proto, buf);

	kobject_reply_errcode(vreq->handle, proto->token, ret);
}

static int __handle_mount_request(struct vreq *vreq, struct proto *proto, char *buf)
{
	struct vnode *parent = vreq->node;
	struct vnode *node;
	char *source = buf + proto->mount.source_off;
	char *target = buf + proto->mount.target_off;

	if (parent->d_ino != -1)
		return -EPERM;

	if (!check_string(buf, proto->mount.source_off, FILENAME_MAX))
		return -EINVAL;

	if (!check_string(buf, proto->mount.target_off, FILENAME_MAX))
		return -EINVAL;

	if (strlen(target) >= VNODENAME_MAX)
		return -EINVAL;

	parent = find_dir_node(parent, source);
	if (!parent)
		return -ENOENT;

	node = alloc_node();
	if (!node)
		return -ENOSPC;

	strcpy(node->name, target);
	if (proto->mount.flags & MS_DIR) {
		node->type = DT_DIR;
		node->handle = 0;
		init_list(&node->child);
		list_add_tail(&parent->child, &node->list);
		kobject_reply_errcode(vreq->handle, proto->token, 0);
	} else {
		node->type = DT_SRV;
		node->handle = kobject_create_port(KR_RWCG, KR_WCG);
		if (node->handle < 0)
			release_node(node);
		else
			list_add_tail(&parent->child, &node->list);
		return node->handle;
	}

	return 0;
}

static void handle_mount_request(struct vreq *vreq, struct proto *proto, char *buf)
{
	int ret = __handle_mount_request(vreq, proto, buf);

	kobject_reply_handle(vreq->handle, proto->token, ret, KR_WC);
}

static int __handle_open_request(struct vreq *vreq,
		struct proto *proto, char *buf, int *remote)
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
			if (cur->type == DT_NOTIFY) {
				if (!(proto->open.flags & O_DIRECTORY))
					return cur->handle;
				else
					return -ENOENT;
			}

			if (!(proto->open.flags & O_DIRECTORY) && (cur->type != DT_DIR))
				return -ENOENT;

			/*
			 * open a directly, create a new endpoint for the request.
			 */
			new_vreq = create_new_vreq(cur);
			if (new_vreq != NULL)
				handle = new_vreq->handle;

			return handle;
		}

		if (cur->type != DT_DIR)
			return -ENOENT;

		end = strchrnul(pathrem, '/');
		if (end - pathrem >= FILENAME_MAX)
			return -ENAMETOOLONG;

		strlcpy(filename, pathrem, end - pathrem + 1);
		pathrem = end;

		next = find_node(cur, filename);
		if (!next)
			return -ENOENT;

		/*
		 * if this node is a service node, open it with remote call.
		 */
		if ((next->type == DT_SRV)) {
			*remote = 1;
			return open_remote_node(next, proto, pathrem);
		}
	}

	return -ENOENT;
}

static void handle_open_request(struct vreq *vreq, struct proto *proto, char *buf)
{
	int remote = 0;
	int handle;

	handle = __handle_open_request(vreq, proto, buf, &remote);
	kobject_reply_handle(vreq->handle, proto->token, handle, KR_WMG);

	if (handle > 0 && remote)
		kobject_close(handle);
}

static void handle_getdent_request(struct vreq *vreq, struct proto *proto, char *buf)
{
	struct vnode *node = vreq->node;
	unsigned char *tmp = vreq->buf;
	struct dirent *de;
	int ret, len;
	struct vnode *next;
	int size_left = PAGE_SIZE;

	if (node->type != DT_DIR) {
		ret = -EBADF;
		goto out;
	}

	if (vreq->pdata == NULL) {
		ret = -EPERM;
		goto out;
	}

	for (;;) {
		if (vreq->pdata == &vreq->node->child)
			ret = 0;

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
		vreq->pdata = vreq->pdata->next;
	}

	ret = PAGE_SIZE - size_left;
out:
	kobject_reply(node->handle, proto->token, ret, 0, 0);
}

static int handle_event(struct epoll_event *event)
{
	struct vreq *vreq = (struct vreq *)event->data.ptr;
	struct proto proto;
	int ret;

	ret = kobject_read_proto_with_string(vreq->handle, &proto,
			string_buffer, FILENAME_MAX, 0);
	if (ret)
		return ret;

	if ((vreq->buf == NULL) && (proto.proto_id == PROTO_GETDENT)) {
		kobject_reply_errcode(vreq->handle, proto.token, -EPERM);
		return -EPERM;
	}

	switch (proto.proto_id) {
	case PROTO_OPEN:
		handle_open_request(vreq, &proto, string_buffer);
		break;
	case PROTO_GETDENT:
		handle_getdent_request(vreq, &proto, string_buffer);
		break;
	case PROTO_MOUNT:
		handle_mount_request(vreq, &proto, string_buffer);
		break;
	case PROTO_UNMOUNT:
		handle_unmount_request(vreq, &proto, string_buffer);
		break;
	case PROTO_READ:
	case PROTO_WRITE:
	case PROTO_IOCTL:
	default:
		ret = -EPERM;
		break;
	};

	return ret;
}

static int sns_loop(int handle)
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

	for (;;) {
		ret = epoll_wait(epfd, events, MAX_EVENTS, -1);
		if (ret) {
			pr_err("vfs epoll failed\n");
			continue;
		}

		for (i = 0; i < ret; i++) {
			if (events[i].data.type != EPOLLIN_WRITE)
				handle_kernel_event(&events[i]);
			else
				handle_event(&events[i]);
		}
	}

	return -1;
}

static void root_vnode_init(void)
{
	strcpy(root_vnode.name, "/");
	root_vnode.type = DT_DIR;
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
int main(int handle, char **argv)
{
	vnodes_init();
	vreqs_init();

	exit(sns_loop(handle));
}
