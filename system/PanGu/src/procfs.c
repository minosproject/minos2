/*
 * Copyright (c) 2021 Min Le (lemin9538@163.com)
 * Copyright (c) 2021 上海网返科技
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/epoll.h>

#include <minos/list.h>
#include <minos/debug.h>
#include <minos/kmalloc.h>
#include <minos/compiler.h>
#include <minos/kobject.h>
#include <minos/types.h>
#include <minos/proto.h>

#include <libminos/file.h>

#include <pangu/request.h>
#include <pangu/proc.h>

static char strbuf[FILENAME_MAX];
static struct file root_file;

static struct file *create_procfs_file(struct proto *proto, struct process *proc)
{
	struct file *file;
	int ret;

	file = create_file(proto->open.flags, proto->open.mode);
	if (!file)
		return NULL;

	/*
	 * if the proc is NULL, means open the root directory.
	 */
	if (proc == NULL)
		file->pdata = list_first_entry(&process_list, struct process, list);
	else
		proc->pdata = proc;

	ret = register_request_entry(REQUEST_TYPE_PROCFS, file->handle, file);
	if (ret) {
		release_file(file);
		file = NULL;
	}

	return file;
}

static long procfs_handle_open_request(struct file *file,
		struct proto *proto, char *buf)
{
	struct file *new_file;
	struct process *proc;
	char *pathrem = buf;

	if (!(file->f_flags & F_FLAGS_ROOT))
		return -ENOENT;

	while (*pathrem == '/')
		pathrem++;

	/*
	 * open the root directory of procfs, procfs only provide two file type
	 * one is the rootdir another is the process.
	 */
	if (*pathrem == '\0') {
		if (!(proto->open.flags & O_DIRECTORY))
			return -ENOENT;

		proc = NULL;
	} else {
		proc = find_process_by_name(pathrem);
		if (!proc)
			return -ENOENT;
	}

	new_file = create_procfs_file(proto, proc);
	if (!new_file)
		return -ENOMEM;

	return new_file->handle;
}

static long procfs_handle_getdent_request(struct file *file,
		struct proto *proto, char *buf)
{
	struct process *proc = file->pdata;
	void *data = file->sbuf;
	struct dirent *de;
	int size_left = PAGE_SIZE, len;
	struct list_head *next;

	if (!(file->f_flags & O_DIRECTORY))
		return -EINVAL;

	for (;;) {
		if (proc == NULL)
			break;

		len = DIRENT_SIZE(strlen(proc->name) + 1);
		if (size_left < len)
			break;

		de = (struct dirent *)data;
		de->d_ino = proc->pid;
		de->d_off = proc->pid;
		de->d_reclen = len;
		de->d_type = DT_REG;
		strcpy(de->d_name, proc->name);

		data += len;
		next = proc->list.next;
		if (next == &process_list)
			file->pdata = NULL;
		else
			file->pdata = list_entry(next, struct process, list);
	}

	return PAGE_SIZE - size_left;
}

static long procfs_handle_read_request(struct file *file, struct proto *proto, char *buf)
{
	return 0;
}

int handle_procfs_event(struct file *file, struct request_entry *re)
{
	struct proto proto;
	long ret;

	ret = kobject_read_proto_with_string(file->handle, &proto, strbuf, FILENAME_MAX, -1);
	if (ret < 0)
		return ret;

	if ((file->f_flags & F_FLAGS_ROOT) && (proto.proto_id != PROTO_OPEN))
		return -EPERM;

	switch (proto.proto_id) {
	case PROTO_OPEN:
		ret = procfs_handle_open_request(file, &proto, strbuf);
		kobject_reply_handle(file->handle, proto.token, ret, KR_W);
		break;
	case PROTO_READ:
		ret = procfs_handle_read_request(file, &proto, strbuf);
		kobject_reply_errcode(file->handle, proto.token, ret);
		break;
	case PROTO_GETDENT:
		ret = procfs_handle_getdent_request(file, &proto, strbuf);
		kobject_reply_errcode(file->handle, proto.token, ret);
		break;
	default:
		kobject_reply_errcode(file->handle, proto.token, -EACCES);
		ret = -EACCES;
		break;
	}

	return ret;
}

static void handle_procfs_close_event(struct file *file, struct request_entry *re)
{
	/*
	 * TBD
	 */
}

void handle_procfs_request(struct epoll_event *event, struct request_entry *re)
{
	struct file *file = (struct file *)re->data;

	switch (event->events) {
	case EPOLLIN:
		handle_procfs_event(file, re);
		break;
	case EPOLLWCLOSE:
		handle_procfs_close_event(file, re);
		break;
	default:
		pr_err("unknow request for procfs\n");
		break;
	}
}

void procfs_init(void)
{
	int rootfd = 0;

	// rootfd = register_service("/", "proc", DT_SRV);
	// if (rootfd <= 0)
	//	exit(-ENOSPC);

	root_file.f_flags |= F_FLAGS_ROOT;
	root_file.handle = rootfd;

	if (register_request_entry(REQUEST_TYPE_PROCFS, rootfd, &root_file)) {
		pr_err("register procfs service failed\n");
		exit(-1);
	}
}
