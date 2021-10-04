/*
 * Copyright (c) 2021 Min Le (lemin9538@163.com)
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
#include <minos/compiler.h>
#include <minos/kobject.h>
#include <minos/types.h>
#include <minos/proto.h>
#include <minos/service.h>

#include <pangu/kmalloc.h>
#include <pangu/request.h>
#include <pangu/proc.h>

struct file {
	uint8_t root;
	uint8_t type;
	int f_flags;
	int handle;
	int sbuf_size;
	void *sbuf;
	struct process *pdata;
};

#define FILE_RIGHT	(KOBJ_RIGHT_RW | KOBJ_RIGHT_MMAP)
#define FILE_REQ_RIGHT	(KOBJ_RIGHT_READ | KOBJ_RIGHT_MMAP)

static char strbuf[FILENAME_MAX];
static struct file root_file;

static struct file *create_file(int flags, int mode)
{
	struct file *f;
	int handle;
	void *addr;

	handle = kobject_create_endpoint(FILE_RIGHT, FILE_REQ_RIGHT, PAGE_SIZE);
	if (handle <= 0)
		return NULL;

	addr = kobject_mmap(handle);
	if (addr == (void *)-1) {
		kobject_close(handle);
		return NULL;
	}

	f = kzalloc(sizeof(struct file));
	if (f == NULL) {
		kobject_close(handle);
		return NULL;
	}

	f->f_flags = flags;
	f->sbuf_size = PAGE_SIZE;
	f->sbuf = addr;
	f->handle = handle;
	f->pdata = NULL;

	return f;
}

static void release_file(struct file *file)
{
	if (!file)
		return;

	kobject_munmap(file->handle);
	kobject_close(file->handle);
	kfree(file);
}

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
		file->pdata = proc;

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

	if (!file->root)
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

	if (file->root && (proto.proto_id != PROTO_OPEN))
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

static int register_procfs_service(const char *src, const char *target, int type, int flags)
{
	char string[FILENAME_MAX];
	struct proto proto;
	char *buf = string;
	int len;

	len = strlen(src) + strlen(target) + 2;
	if (len >= FILENAME_MAX)
		return -ENAMETOOLONG;

	strcpy(buf, src);
	buf += strlen(src) + 1;
	strcpy(buf, target);

	proto.proto_id = PROTO_REGISTER_SERVICE;
	proto.register_service.type = type;
	proto.register_service.flags = flags;
	proto.register_service.source_off = 0;
	proto.register_service.target_off = strlen(src) + 1;

	return kobject_write(fuxi_handle, &proto,
			sizeof(struct proto), string, len, -1);
}

void procfs_init(void)
{
	int rootfd = 0;

	rootfd = register_procfs_service("/", "proc", SRV_PORT, 0);
	if (rootfd <= 0)
		exit(-ENOSPC);

	root_file.handle = rootfd;
	root_file.root = 1;

	if (register_request_entry(REQUEST_TYPE_PROCFS, rootfd, &root_file)) {
		pr_err("register procfs service failed\n");
		exit(-1);
	}
}
