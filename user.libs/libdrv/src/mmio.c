/*
 * Copyright (c) 2020 - 2021 Min Le (lemin9538@163.com)
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <minos/kobject.h>

void *request_mmio_by_handle(int handle)
{
	if (kobject_open(handle) < 0)
		return (void *)-1;

	return kobject_mmap(handle);
}
