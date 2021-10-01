/*
 * Copyright (c) 2021 Min Le (lemin9538@163.com)
 */

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <minos/debug.h>
#include <minos/types.h>

void *ext4_user_malloc(size_t size)
{
	void *mem;

	mem = malloc(size);
	if (mem)
		memset(mem, 0, size);

	return mem;
}

void *ext4_user_calloc(size_t numb, size_t size)
{
	return ext4_user_malloc(numb * size);
}

void ext4_user_free(void *mem)
{
	free(mem);
}

void *ext4_realloc(void *ptr, size_t size)
{
	pr_err("ext4_realloc do not implement\n");

	return NULL;
}

void *ext4_user_alloc_bcache(size_t size)
{
	void *mem;

	mem = memalign(PAGE_SIZE, PAGE_BALIGN(size));
	if (mem)
		memset(mem, 0, sizeof(unsigned long));

	return mem;
}
