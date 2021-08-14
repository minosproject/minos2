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
#include <pangu/request.h>

static LIST_HEAD(request_entry_list);
static int proc_epfd;
int fuxi_handle;

#define MAX_EVENT 16

struct request_entry *register_request_entry(int type, int handle, void *data)
{
	struct request_entry *re;

	re = kzalloc(sizeof(struct request_entry));
	if (!re) {
		pr_err("register request entry failed %d\n", type);
		return re;
	}

	re->type = type;
	re->handle = handle;
	re->data = data;
	list_add_tail(&request_entry_list, &re->list);

	return re;
}

static void handle_event(struct epoll_event *event)
{
	struct request_entry *re = event->data.ptr;
	int ret;

	if (!re) {
		pr_err("invalid event receive\n");
		return;
	}

	switch (re->type) {
	case REQUEST_TYPE_PROCESS:
		ret = handle_process_request(event, re);
		break;
	default:
		pr_err("invalid request type %d\n", re->type);
		ret = -EINVAL;
		break;
	}

	if (ret < 0)
		pr_err("handle request failed\n");
}

void pangu_main(void)
{
	struct epoll_event events[MAX_EVENT];
	struct epoll_event *event = &events[0];
	struct request_entry *re;
	long ret;
	int i;

	proc_epfd = epoll_create(MAX_EVENT);
	if (proc_epfd < 0) {
		pr_err("can not create epoll fd\n");
		exit(-ENOENT);
	}

	/*
	 * poll the request entry which already register during pangu
	 * boot stage.
	 */
	list_for_each_entry(re, &request_entry_list, list) {
		event->events = EPOLLIN;
		event->data.ptr = re;

		if (epoll_ctl(proc_epfd, EPOLL_CTL_ADD, re->handle, event))
			pr_err("epoll %d %d failed\n", re->type, re->handle);
	}

	/*
	 * wake up all the process which created by PanGu itself.
	 */
	wakeup_all_process();

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
