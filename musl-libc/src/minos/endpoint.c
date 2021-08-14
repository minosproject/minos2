/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"
#include <sys/epoll.h>
#include <minos/kobject.h>
#include <minos/types.h>

static inline int __kobject_create_endpoint(int right, int right_req,
		size_t shmem_size, int mutil_w)
{
	struct endpoint_create_arg args;
	int mode;

	mode = mutil_w ? EP_MODE_MUTIL_WRITER : EP_MODE_NORMAL;
	shmem_size = (mutil_w ? 0 : PAGE_BALIGN(shmem_size));
	args.mode = mode;
	args.shmem_size = shmem_size;

	return kobject_create(KOBJ_TYPE_ENDPOINT, right,
			right_req, (unsigned long)&args);
}

int kobject_create_endpoint(int right, int right_req, size_t shmem_size)
{
	return __kobject_create_endpoint(right, right_req, shmem_size, 0);
}

int kobject_create_port(int right, int right_req)
{
	return __kobject_create_endpoint(right, right_req, 0, 1);
}
