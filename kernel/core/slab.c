/*
 * Copyright (C) 2018 Min Le (lemin9538@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <minos/types.h>
#include <config/config.h>
#include <minos/spinlock.h>
#include <minos/minos.h>
#include <minos/init.h>
#include <minos/page.h>
#include <minos/slab.h>
#include <minos/poll.h>

#define HASH_TABLE_SIZE	8

#define SLAB_MEM_BASE ptov(511UL * 1024 * 1024 * 1024)
#define SLAB_MEM_SIZE (128UL * 1024 * 1024)
#define SLAB_MEM_END (SLAB_MEM_BASE + SLAB_MEM_SIZE)

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
static DEFINE_SPIN_LOCK(slab_lock);
static struct list_head slab_hash_table[HASH_TABLE_SIZE];

static void *slab_base;
static uint32_t slab_size;
static uint32_t cur_free_size;

#define hash_id(size) (((size) >> SLAB_MIN_DATA_SIZE_SHIFT) % HASH_TABLE_SIZE)

static int inline is_slab_memory(void *addr)
{
	return (((unsigned long)addr >= SLAB_MEM_BASE) &&
			((unsigned long)addr < SLAB_MEM_END));
}

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
	unsigned long base = 0;
	struct slab_header *sh;
	uint32_t mapsize;
	void *page;
	int i;

	size += SLAB_HEADER_SIZE;
	if (slab_size < size)
		return NULL;

	if (cur_free_size >= size) {
		mapsize = 0;
		cur_free_size -= size;
	} else {
		base = (unsigned long)slab_base + cur_free_size;
		mapsize = PAGE_BALIGN(size - cur_free_size);
		cur_free_size = cur_free_size + mapsize - size;
	}

	/*
	 * if need one new page, need to allocate the needed
	 * pages and map it.
	 */
	for (i = 0; i < (mapsize >> PAGE_SHIFT); i++) {
		page = get_free_page(GFP_KERNEL | GFP_SLAB);
		ASSERT(page != NULL);
		ASSERT(create_host_mapping(base, vtop(page),
				PAGE_SIZE, VM_HOST | VM_RW) == 0);
		base += PAGE_SIZE;
	}

	sh = (struct slab_header *)slab_base;
	sh->magic = SLAB_MAGIC;
	sh->size = size - SLAB_HEADER_SIZE;

	slab_base += size;
	slab_size -= size;

	return ((void *)sh + SLAB_HEADER_SIZE);
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
		pr_warn("memory is not a slab mem 0x%p\n", (unsigned long)addr);
		return;
	}

	id = hash_id(header->size);
	spin_lock(&slab_lock);

	list_for_each_entry(st, &slab_hash_table[id], list) {
		if (st->size != header->size)
			continue;

		header->next = st->head;
		st->head = header;
		spin_unlock(&slab_lock);
		return;
	}

	/*
	 * create new slab type and add the new slab header
	 * to the slab cache.
	 */
	st = malloc_from_slab_heap(sizeof(struct slab_type));
	ASSERT(st != NULL);
	pr_debug("create new slab type for %d %d\n",
			header->size, id);
	st->size = header->size;
	list_add_tail(&slab_hash_table[id], &st->list);

	header->next = NULL;
	st->head = header;

	spin_unlock(&slab_lock);
}

void add_slab_mem(unsigned long base, size_t size)
{
	/*
	 * all the free memory will cached for poll_event_kernel
	 */
	int pesize = get_slab_alloc_size(sizeof(struct poll_event_kernel));
	struct slab_header *header;

	while (size > (pesize + SLAB_HEADER_SIZE)) {
		header = (struct slab_header *)base;
		header->magic = SLAB_MAGIC;
		header->size = pesize;

		free_slab((void *)header);

		base += (pesize + SLAB_HEADER_SIZE);
		size -= (pesize + SLAB_HEADER_SIZE);
	}
}

void free(void *addr)
{
	if (!is_slab_memory(addr)) {
		if (free_pages(addr) == 0)
			return;
	}

	free_slab(addr);
}

static void *__malloc(size_t size)
{
	void *mem;

	spin_lock(&slab_lock);
	mem = malloc_from_hash_table(size);
	if (mem == NULL)
		mem = malloc_from_slab_heap(size);
	spin_unlock(&slab_lock);

	if (!mem) {
		pr_err("malloc fail for 0x%x\n");
		dump_stack(NULL, NULL);
		BUG();
	}

	return mem;
}

void *malloc(size_t size)
{
	ASSERT(size != 0);
	size = get_slab_alloc_size(size);
	return __malloc(size);
}

void *zalloc(size_t size)
{
	void *addr = malloc(size);
	if (addr)
		memset(addr, 0, size);
	return addr;
}

void slab_init(void)
{
	int i;

	pr_notice("slab memory allocator init ...\n");
	slab_base = (void *)SLAB_MEM_BASE;
	slab_size = SLAB_MEM_SIZE;

	for (i = 0; i < HASH_TABLE_SIZE; i++)
		init_list(&slab_hash_table[i]);
}
