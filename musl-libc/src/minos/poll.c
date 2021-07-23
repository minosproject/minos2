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
	ssize_t size;

	/*
	 * currently only support EPOLLIN event
	 */
	if ((events == NULL) || (maxevents <= 0))
		return -EINVAL;

	size = maxevents * sizeof(struct epoll_event);
	size = kobject_read(epfd, events, size, NULL, 0, timeout);
	if (size < 0)
		return size;
	else if (size == 0)
		return -EAGAIN;

	return (size / sizeof(struct epoll_event));
}

int epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
		int timeout, const sigset_t *sig)
{
	return -ENOSYS;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	if ((op != EPOLL_CTL_ADD) || (op != EPOLL_CTL_DEL)
			|| (op != EPOLL_CTL_MOD) || (!event))
		return -EINVAL;

	op += KOBJ_POLL_HUB_OP_BASE;
	event->data.fd = fd;

	return kobject_ctl(epfd, op, (unsigned long)event);
}

int epoll_create(int size)
{
	return kobject_create(NULL, KOBJ_TYPE_POLL_HUB,
			KOBJ_RIGHT_READ | KOBJ_RIGHT_CTL,
			KOBJ_RIGHT_READ | KOBJ_RIGHT_CTL, 0);
}

int epoll_create1(int flags)
{
	return epoll_create(0);
}
