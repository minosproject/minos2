/*
 * Copyright (c) 2020 - 2021 Min Le (lemin9538@163.com)
 */

#include <stdlib.h>
#include "libc.h"
#include <string.h>

#include <minos/kmalloc.h>

void *libc_malloc(size_t size)
{
	if (libc.use_kmalloc)
		return kmalloc(size);
	else
		return malloc(size);
}

void *libc_zalloc(size_t size)
{
	void *addr;

	addr = libc_malloc(size);
	if (addr)
		memset(addr, 0, size);
	return addr;
}

void libc_free(void *p)
{
	if (libc.use_kmalloc)
		kfree(p);
	else
		free(p);
}
