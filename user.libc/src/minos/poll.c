/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"
#include <sys/epoll.h>
#include <minos/kobject.h>

int epoll_wait(int epfd, struct epoll_event *events,
                      int maxevents, int timeout)
{
	size_t e, d;
	ssize_t size;
	int ret;

	/*
	 * currently only support EPOLLIN event
	 */
	if ((events == NULL) || (maxevents <= 0))
		return -EINVAL;

	size = maxevents * sizeof(struct epoll_event);
	ret = kobject_read(epfd, events, size, &d, NULL, 0, &e, timeout);
	if (ret < 0)
		return ret;
	else if (d == 0)
		return -EAGAIN;

	return (d / sizeof(struct epoll_event));
}

int epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
		int timeout, const sigset_t *sig)
{
	return -ENOSYS;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	if (!event)
		return -EINVAL;

	if ((op != EPOLL_CTL_ADD) && (op != EPOLL_CTL_DEL) && (op != EPOLL_CTL_MOD))
		return -EINVAL;

	op += KOBJ_POLLHUB_OP_BASE;
	event->data.fd = fd;

	return kobject_ctl(epfd, op, (unsigned long)event);
}

int epoll_create(int size)
{
	return kobject_create(KOBJ_TYPE_POLLHUB, 0);
}

int epoll_create1(int flags)
{
	return epoll_create(0);
}
