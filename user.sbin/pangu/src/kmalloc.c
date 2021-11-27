/*
 * Copyright (c) 2020 - 2021 Min Le (lemin9538@163.com)
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <string.h>

#include <minos/types.h>
#include <minos/list.h>
#include <minos/debug.h>

#define HASH_TABLE_SIZE	8

struct slab_header {
	unsigned long size;
	union {
		unsigned long magic;
		struct slab_header *next;
	};
} __packed;

#define SLAB_MIN_DATA_SIZE		(16)
#define SLAB_MIN_DATA_SIZE_SHIFT	(4)
#define SLAB_HEADER_SIZE		sizeof(struct slab_header)
#define SLAB_MIN_SIZE			(SLAB_MIN_DATA_SIZE + SLAB_HEADER_SIZE)
#define SLAB_MAGIC			(0xdeadbeef)

struct slab_type {
	uint32_t size;
	struct list_head list;
	struct slab_header *head;
};

/*
 * will try to get hugepage when first time once
 * system bootup.
 */
static struct list_head slab_hash_table[HASH_TABLE_SIZE];

static void *slab_base;
static void *slab_end;
static uint32_t slab_size;

#define hash_id(size) (((size) >> SLAB_MIN_DATA_SIZE_SHIFT) % HASH_TABLE_SIZE)

static size_t inline get_slab_alloc_size(size_t size)
{
	return BALIGN(size, SLAB_MIN_DATA_SIZE);
}

static void *malloc_from_hash_table(size_t size)
{
	int id = hash_id(size);
	struct slab_type *st;
	struct slab_header *sh;

	/*
	 * find the related slab mem id and try to fetch
	 * a free slab memory from the hash cache.
	 */
	list_for_each_entry(st, &slab_hash_table[id], list) {
		if (st->size != size)
			continue;

		if (st->head == NULL)
			return NULL;

		sh = st->head;
		st->head = sh->next;
		sh->magic = SLAB_MAGIC;

		return ((void *)sh + SLAB_HEADER_SIZE);
	}

	return NULL;
}

static void *malloc_from_slab_heap(size_t size)
{
	struct slab_header *sh;

	size += SLAB_HEADER_SIZE;
	if (slab_size < size)
		return NULL;

	sh = (struct slab_header *)slab_base;
	sh->magic = SLAB_MAGIC;
	sh->size = size - SLAB_HEADER_SIZE;

	slab_base += size;
	slab_size -= size;

	return ((void *)sh + SLAB_HEADER_SIZE);
}

static void xxx_debug(void)
{
	printf("xxx debug\n");
}

static void free_slab(void *addr)
{
	struct slab_header *header;
	struct slab_type *st;
	int id;

	header = (struct slab_header *)((unsigned long)addr -
			SLAB_HEADER_SIZE);
	if ((header->magic != SLAB_MAGIC) ||
			(header->size < SLAB_MIN_DATA_SIZE)) {
		xxx_debug();
		pr_warn("memory is not a slab mem %p\n", addr);
		return;
	}

	id = hash_id(header->size);

	list_for_each_entry(st, &slab_hash_table[id], list) {
		if (st->size != header->size)
			continue;

		header->next = st->head;
		st->head = header;
		return;
	}

	/*
	 * create new slab type and add the new slab header
	 * to the slab cache.
	 */
	st = malloc_from_slab_heap(sizeof(struct slab_type));
	if (st == NULL) {
		pr_err("no more memory for pangu\n");
		exit(-ENOMEM);
	}

	st->size = header->size;
	list_add_tail(&slab_hash_table[id], &st->list);

	header->next = NULL;
	st->head = header;
}

void kfree(void *addr)
{
	free_slab(addr);
}

static void *__malloc(size_t size)
{
	void *mem;

	mem = malloc_from_hash_table(size);
	if (mem == NULL)
		mem = malloc_from_slab_heap(size);
	if (!mem)
		pr_err("malloc fail for 0x%lx\n", size);

	return mem;
}

void *kmalloc(size_t size)
{
	if (size == 0)
		size = SLAB_MIN_DATA_SIZE;
	else
		size = get_slab_alloc_size(size);

	return __malloc(size);
}

void *kzalloc(size_t size)
{
	void *addr = kmalloc(size);
	if (addr)
		memset(addr, 0, size);
	return addr;
}

void *get_pages(int count)
{
	return kmalloc(4096);
}

void free_pages(void *base)
{
	return kfree(base);
}

int kmalloc_init(unsigned long base, unsigned long end)
{
	int i;

	if ((end < base) || !IS_PAGE_ALIGN(base) || !IS_PAGE_ALIGN(end)) {
		fprintf(stderr, "invalid heap region 0x%lx 0x%lx\n", base, end);
		return -EINVAL;
	}

	/*
	 * caculate the real free memory that the process
	 * can be used.
	 */
	slab_base = (void *)base;
	slab_end = (void *)end;
	slab_size = end - base;

	for (i = 0; i < HASH_TABLE_SIZE; i++)
		init_list(&slab_hash_table[i]);

	return 0;
}
