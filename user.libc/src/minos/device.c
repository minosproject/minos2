/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "stdio_impl.h"
#include "libc.h"
#include <minos/proto.h>
#include <minos/kobject.h>
#include <minos/types.h>

static int __request_device_resource(int id, const char *comp, int index)
{
	struct proto proto;

	if (libc.chiyou_handle <= 0)
		return -EPERM;

	if (strlen(comp) >= FILENAME_MAX)
		return -ENAMETOOLONG;

	proto.proto_id = id;
	proto.devinfo.key = 0;
	proto.devinfo.index = index;

	return kobject_write(libc.chiyou_handle, &proto,
			sizeof(struct proto), (void *)comp, strlen(comp), -1);
}

int request_irq_by_handle(int handle)
{
	return kobject_open(handle);
}

int request_consequent_pma(size_t memsize, int right)
{
	return kobject_create_consequent_pma(memsize, right);
}

void *request_mmio_by_handle(int handle)
{
	void *base;

	if (kobject_open(handle) < 0)
		return (void *)-1;

	if (kobject_mmap(handle, &base, NULL))
			return (void *)-1;

	return base;
}

int get_device_mmio_handle(const char *comp, int index)
{
	return __request_device_resource(PROTO_GET_MMIO, comp, index);
}

int get_device_irq_handle(const char *comp, int index)
{
	return __request_device_resource(PROTO_GET_IRQ, comp, index);
}
