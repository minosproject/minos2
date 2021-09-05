/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"
#include <sys/epoll.h>
#include <minos/kobject.h>
#include <minos/types.h>

int kobject_create_endpoint(int right, int right_req, size_t shmem_size)
{
	return kobject_create(KOBJ_TYPE_ENDPOINT, right, right_req, shmem_size);
}

int kobject_create_socket(int right, int right_req, size_t shmem_size)
{
	return kobject_create(KOBJ_TYPE_SOCKET, right, right_req, shmem_size);
}

int kobject_create_port(int right, int right_req)
{
	return kobject_create(KOBJ_TYPE_PORT, right, right_req, 0);
}

int kobject_create_notify(int right, int right_req)
{
	return kobject_create(KOBJ_TYPE_NOTIFY, right, right_req, 0);
}

int kobject_create_pma(int right, int right_req, size_t memsize)
{
	int nr = PAGE_NR(memsize);
	struct pma_create_arg args;

	args.cnt = nr;
	args.type = PMA_TYPE_NORMAL;
	args.start = 0;
	args.end = 0;

	return kobject_create(KOBJ_TYPE_PMA, right, right_req, (unsigned long)&args);
}
