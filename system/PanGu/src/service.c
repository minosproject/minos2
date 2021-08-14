/*
 * Copyright (C) 2021 Min Le (lemin9538@163.com)
 */

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/epoll.h>

#include <minos/kobject.h>
#include <minos/map.h>
#include <minos/debug.h>
#include <minos/list.h>
#include <minos/kmalloc.h>
#include <minos/proto.h>

#include <pangu/vma.h>
#include <pangu/proc.h>
#include <pangu/service.h>

LIST_HEAD(service_list);

#define SERVICE_INIT_RIGHT \
	(KOBJ_RIGHT_RW | KOBJ_RIGHT_GRANT)

static inline struct service *find_service(char *name)
{
	struct service *srv;

	list_for_each_entry(srv, &service_list, list) {
		if (strcmp(srv->name, name) == 0)
			return srv;
	}

	return NULL;
}

int process_connect_service(struct process *proc, char *name,
		struct proto_connect_srv *proto)
{
	struct service *srv;

	srv = find_service(name);
	if (!srv)
		return -EINVAL;

	if ((proto->right & KOBJ_RIGHT_RW) == srv->right)
		return -EPERM;

	return srv->handle;
}

int process_unregister_service(struct process *proc, char *name)
{
	struct service *srv;

	srv = find_service(name);
	if (!srv)
		return -ENOENT;

	list_del(&srv->list);
}

int process_register_service(struct process *proc, char *name,
		struct proto_register_srv *proto)
{
	struct service *srv;
	struct endpoint_create_arg args;
	int handle;
	int right = SERVICE_INIT_RIGHT;

	if (proto->right == KOBJ_RIGHT_RW)
		return -EINVAL;

	if (proto->mutil_client && (proto->shmem_size > 0))
		return -EINVAL;

	srv = find_service(name);
	if (srv)
		return -EEXIST;

	args.mode = proto->mutil_client ? EP_MODE_MUTIL_WRITER : EP_MODE_NORMAL;
	args.shmem_size = proto->shmem_size;
	if (args.shmem_size > 0)
		right |= KOBJ_RIGHT_MMAP;

	handle = kobject_create(NULL, KOBJ_TYPE_ENDPOINT,
			right, KOBJ_RIGHT_GRANT, &args);
	if (handle <= 0)
		return handle;

	srv = kzalloc(sizeof(struct service));
	if (!srv) {
		kobject_clean(handle);
		return -ENOMEM;
	}

	srv->handle = handle;
	srv->mutil_client = mutil_client;
	srv->right = right;
	srv->proc = process;
	strcpy(srv->name, name);
	list_add_tail(&service_list, &srv->list);

	return handle;
}

int handle_service_info_request(struct epoll_event *event, struct request_entry *re)
{
	struct list_head *list = re->data;
	struct service *srv;
	struct service_info info;

	if (list == &service_list) {
		memset(&info, 0, sizeof(struct service_info));
	} else {
		srv = list_entry(list, struct service, list);
		re->data = (void)list->next;

		strcpy(info.name, srv->name);
		info.right = KOBJ_RIGHT_RW & ~(srv->right);
		info.type = srv->type;
	}

	return kobject_write(re->handle, &info, sizeof(struct service_info), NULL, 0, 0);
}
