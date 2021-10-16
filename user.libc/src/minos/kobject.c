/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"
#include <sys/epoll.h>
#include <minos/kobject.h>
#include <minos/types.h>

int kobject_create_endpoint(size_t shmem_size)
{
	return kobject_create(KOBJ_TYPE_ENDPOINT, shmem_size);
}

int kobject_create_socket(size_t shmem_size)
{
	return kobject_create(KOBJ_TYPE_SOCKET, shmem_size);
}

int kobject_create_port(void)
{
	return kobject_create(KOBJ_TYPE_PORT, 0);
}

int kobject_create_notify(void)
{
	return kobject_create(KOBJ_TYPE_NOTIFY, 0);
}

static int __kobject_create_pma(size_t memsize, int consequent, int right)
{
	struct pma_create_arg args;

	args.size = memsize;
	args.right = right;
	args.consequent = consequent;
	args.type = PMA_TYPE_NORMAL;
	args.start = 0;

	return kobject_create(KOBJ_TYPE_PMA, (unsigned long)&args);
}

int kobject_create_pma(size_t memsize, int right)
{
	return __kobject_create_pma(memsize, 0, right);
}

int kobject_create_consequent_pma(size_t memsize, int right)
{
	return __kobject_create_pma(memsize, 1, right);
}
