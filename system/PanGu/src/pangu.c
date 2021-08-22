/*
 * Copyright (C) 2021 Min Le (lemin9538@163.com)
 * Copyright (c) 2021 上海网返科技
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
#include <pangu/request.h>

static LIST_HEAD(request_entry_list);
int proc_epfd;
int fuxi_handle;
extern struct process *rootfs_proc;

#define MAX_EVENT 16

static struct request_entry *alloc_request_entry(int type, void *data)
{
	struct request_entry *re;

	re = kzalloc(sizeof(struct request_entry));
	if (!re) {
		pr_err("register request entry failed %d\n", type);
		return re;
	}

	re->type = type;
	re->data = data;
	list_add_tail(&request_entry_list, &re->list);

	return re;
}

int register_request_entry(int type, int handle, void *data)
{
	struct request_entry *re;
	struct epoll_event event;

	re = alloc_request_entry(type, data);
	if (!re)
		return -ENOMEM;

	event.events = EPOLLIN;
	event.data.ptr = data;

	return epoll_ctl(proc_epfd, EPOLL_CTL_ADD, handle, &event);
}

static void handle_event(struct epoll_event *event)
{
	struct request_entry *re = event->data.ptr;

	if (!re) {
		pr_err("invalid event receive\n");
		return;
	}

	switch (re->type) {
	case REQUEST_TYPE_PROCESS:
		handle_process_request(event, re);
		break;
	case REQUEST_TYPE_PROCFS:
		handle_procfs_request(event, re);
		break;
	default:
		pr_err("invalid request type %d\n", re->type);
		break;
	}
}

void pangu_main(void)
{
	struct epoll_event events[MAX_EVENT];
	struct epoll_event *event = &events[0];
	long ret;
	int i;

	/*
	 * wake up all the process which created by PanGu itself.
	 * currently only need to wake up the rootfs driver process.
	 */
	wakeup_process(rootfs_proc);

	for (;;) {
		ret = epoll_wait(proc_epfd, events, MAX_EVENT, -1);
		if (ret <= 0 || ret > MAX_EVENT) {
			pr_err("failed wait for event try again %d?\n", ret);
			continue;
		}

		for (i = 0; i < ret; i++)
			handle_event(&event[i]);
	}
}
