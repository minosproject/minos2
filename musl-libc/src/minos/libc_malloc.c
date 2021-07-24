/*
 * Copyright (c) 2020 - 2021 Min Le (lemin9538@163.com)
 */

#include <stdlib.h>
#include "libc.h"

#include <minos/kmalloc.h>

void *libc_malloc(size_t size)
{
	if (libc.use_kmalloc)
		return kmalloc(size);
	else
		return malloc(size);
}

void libc_free(void *p)
{
	if (libc.use_kmalloc)
		kfree(p);
	else
		free(p);
}
