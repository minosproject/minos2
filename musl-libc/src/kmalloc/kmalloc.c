/*
 * Copyright (c) 2020 - 2021 Min Le (lemin9538@163.com)
 */

#include <strings.h>
#include <errno.h>
#include <string.h>
#include "libc.h"
#include "lock.h"
#include "syscall.h"

#include <minos/types.h>
#include <minos/list.h>

struct mem_meta {
	void *addr;
	int ispage;
	unsigned long size;
	struct list_head list;
};

struct list_head slab_free_list;
struct list_head page_free_list;
struct list_head slab_use_list;
struct list_head page_use_list;

static unsigned long heap_pool_base;
static unsigned long heap_pool_end;

static int kmalloc_has_init;

static volatile int lock[1];
volatile int *const __kmalloc_lockptr = lock;

static void *get_memory_unlock(size_t size, int ispage)
{
	unsigned long start, end;

	if (ispage && (!IS_PAGE_ALIGN(size))) {
		fprintf(stderr, "kmalloc: memory size not correct\n");
		return NULL;
	}

	if (ispage) {
		start = heap_pool_end - size;
		if (start < heap_pool_base)
			return NULL;

		heap_pool_end = start;
		return (void *)start;
	} else {
		end = heap_pool_base + size;
		if (end > heap_pool_end)
			return NULL;

		start = heap_pool_base;
		heap_pool_base = end;
		return (void *)start;
	}
}

/*
 * malloc will re-designed which only allocated the kernel
 * object, such as task process stack and others
 */
static void *malloc_internal(size_t size, int ispage)
{
	struct mem_meta *ret = NULL;
	struct mem_meta *meta;
	struct list_head *use_list;
	struct list_head *free_list;
	void *addr;

	if (!kmalloc_has_init) {
		fprintf(stderr, "kmalloc has not inited\n");
		return NULL;
	}

	size = BALIGN(size, sizeof(unsigned long));

	if (ispage) {
		use_list = &page_use_list;
		free_list = &page_free_list;
	} else {
		use_list = &slab_use_list;
		free_list = &slab_free_list;
	}

	LOCK(lock);

	list_for_each_entry(meta, free_list, list) {
		if (meta->size == size) {
			ret = meta;
			break;
		}

		if (meta->size > size) {
			if (!ret)
				ret = meta;

			if (meta->size < ret->size)
				ret = meta;
		}
	}

	if (ret) {
		list_del(&ret->list);
		list_add_tail(use_list, &ret->list);
		addr = ret->addr;
		goto out;
	}

	/*
	 * allocate a new slab with the match size
	 */
	meta = get_memory_unlock(sizeof(struct mem_meta), 0);
	addr = get_memory_unlock(size, ispage);
	if (meta && addr) {
		meta->addr = addr;
		meta->size = size;
		meta->ispage = ispage;
		list_add_tail(use_list, &meta->list);
		goto out;
	}

out:
	UNLOCK(lock);

	return addr;
}

static void mfree_internal(void *addr, int ispage)
{
	struct list_head *use_list, *free_list;
	struct mem_meta *meta, *tmp;

	if (!kmalloc_has_init) {
		fprintf(stderr, "kmalloc has not inited\n");
		return;
	}

	if (ispage) {
		use_list = &page_use_list;
		free_list = &page_free_list;
	} else {
		use_list = &slab_use_list;
		free_list = &slab_free_list;
	}

	LOCK(lock);

	list_for_each_entry_safe(meta, tmp, use_list, list) {
		if (meta->addr == addr) {
			list_del(&meta->list);
			list_add(free_list, &meta->list);
			break;
		}
	}

	UNLOCK(lock);
}

void *kmalloc(size_t size)
{
	return malloc_internal(size, 0);
}

void *kzalloc(size_t size)
{
	void *base;

	base = kmalloc(size);
	if (!base)
		return NULL;

	memset(base, 0, size);
	return base;
}

void kfree(void *addr)
{
	mfree_internal(addr, 0);
}

void *get_pages(int count)
{
	return malloc_internal(count << PAGE_SHIFT, 1);
}

void free_pages(void *base)
{
	mfree_internal(base, 1);
}

hidden int kmalloc_init(unsigned long base, unsigned long end)
{
	if ((end < base) || !IS_PAGE_ALIGN(base) || !IS_PAGE_ALIGN(end)) {
		fprintf(stderr, "invalid heap region 0x%lx 0x%lx\n", base, end);
		return -EINVAL;
	}

	/*
	 * caculate the real free memory that the process
	 * can be used.
	 */
	heap_pool_base = base;
	heap_pool_end = end;

	init_list(&slab_free_list);
	init_list(&page_free_list);
	init_list(&slab_use_list);
	init_list(&page_use_list);
	kmalloc_has_init = 1;

	return 0;
}
