/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"
#include <minos/poll.h>
#include <minos/kobject.h>

int poll_wait(handle_t handle, struct poll_event *events,
		int max_event, uint32_t timeout)
{
	ssize_t size;
	if ((events == NULL) || (max_event <= 0))
		return -EINVAL;

	size = max_event * sizeof(struct poll_event);
	size = kobject_read(handle, events, size, NULL, 0, timeout);
	if (size < 0)
		return size;
	else if (size == 0)
		return -EAGAIN;
	
	return (size / sizeof(struct poll_event));
}
