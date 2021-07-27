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
#include <bitmap.h>

#define PAGE_F_HEAD	(1 << 0)

struct slab_header {
        unsigned long size;
        union {
                unsigned long magic;
                struct slab_header *next;
        };
};

struct slab_pool {
	size_t size;
	struct slab_header *head;
	unsigned long nr;
};

struct slab {
	int pool_nr;
	int free_size;
	unsigned long slab_free;
	struct slab_pool *pool;
	size_t alloc_pages;
};

struct page {
	int count;
	int flags;
} __attribute__((__packed__));

static struct page *pages;
static unsigned long *bitmap;

static unsigned long heap_pool_base;
static unsigned long heap_pool_end;
static size_t page_nr;

static int kmalloc_has_init;

static struct slab slab;
static struct slab *pslab = &slab;

static void inline add_slab_to_slab_pool(struct slab_header *header,
		struct slab_pool *pool);

static volatile int lock[1];
volatile int *const __kmalloc_lockptr = lock;

static struct slab_pool slab_pool[] = {
	{16, 	NULL, 0},
	{32, 	NULL, 0},
	{48, 	NULL, 0},
	{64, 	NULL, 0},
	{80, 	NULL, 0},
	{96, 	NULL, 0},
	{112, 	NULL, 0},
	{128, 	NULL, 0},
	{144, 	NULL, 0},
	{160, 	NULL, 0},
	{176, 	NULL, 0},
	{192, 	NULL, 0},
	{208, 	NULL, 0},
	{224, 	NULL, 0},
	{240, 	NULL, 0},
	{256, 	NULL, 0},
	{272, 	NULL, 0},
	{288, 	NULL, 0},
	{304, 	NULL, 0},
	{320, 	NULL, 0},
	{336, 	NULL, 0},
	{352, 	NULL, 0},
	{368, 	NULL, 0},
	{384, 	NULL, 0},
	{400, 	NULL, 0},
	{416, 	NULL, 0},
	{432, 	NULL, 0},
	{448, 	NULL, 0},
	{464, 	NULL, 0},
	{480, 	NULL, 0},
	{496, 	NULL, 0},
	{512, 	NULL, 0},
	{0, 	NULL, 0},		/* size > 512 and freed by minos will in here */
	{0, 	NULL, 0}		/* size > 512 will store here used as cache pool*/
};

#define SLAB_MIN_DATA_SIZE		(16)
#define SLAB_MIN_DATA_SIZE_SHIFT	(4)
#define SLAB_HEADER_SIZE		sizeof(struct slab_header)
#define SLAB_MIN_SIZE			(SLAB_MIN_DATA_SIZE + SLAB_HEADER_SIZE)
#define SLAB_MAGIC			(0xdeadbeef)
#define SLAB_SIZE(size)			((size) + SLAB_HEADER_SIZE)
#define SLAB_HEADER_TO_ADDR(header)	\
	((void *)((unsigned long)header + SLAB_HEADER_SIZE))
#define ADDR_TO_SLAB_HEADER(base) \
	((struct slab_header *)((unsigned long)base - SLAB_HEADER_SIZE))

#define FREE_POOL_OFFSET		(2)
#define CACHE_POOL_OFFSET		(1)

/*
 * this function is not thread safe, should be only
 * used when there is one thread in this process.
 */
static void *get_pages_unlocked(int count)
{
	struct page *p;
	int bit;

	if ((count <= 0) || !kmalloc_has_init)
		return NULL;

	bit = bitmap_find_next_zero_area(bitmap, page_nr, 0, count, 1);
	if (bit >= page_nr)
		return NULL;

	bitmap_set(bitmap, bit, count);
	p = pages + bit;
	p->flags = PAGE_F_HEAD;
	p->count = count;

	return (void *)(heap_pool_base + (bit << PAGE_SHIFT));
}

void *get_pages(int count)
{
	void *base;

	LOCK(lock);
	base = get_pages_unlocked(count);
	UNLOCK(lock);

	return base;
}

void free_pages(void *base)
{
	struct page *page;
	int bit;

	if (!kmalloc_has_init)
		return;

	if (((unsigned long)base < heap_pool_base) ||
		((unsigned long)base > heap_pool_end) ||
		!IS_PAGE_ALIGN(base)) {
		fprintf(stderr, "free invalid heap memory %p\n", base);
		return;
	}

	LOCK(lock);

	bit = ((unsigned long)base - heap_pool_base) >> PAGE_SHIFT;
	page = pages + bit;
	if (!(page->flags & PAGE_F_HEAD)) {
		fprintf(stderr, "invalid page\n");
		goto out;
	}

	bitmap_clear(bitmap, bit, page->count);
	memset(page, 0, sizeof(struct page));
out:
	UNLOCK(lock);
}

static size_t inline get_slab_alloc_size(size_t size)
{
	return BALIGN(size, SLAB_MIN_DATA_SIZE);
}

static inline int slab_pool_id(size_t size)
{
	int id = (size >> SLAB_MIN_DATA_SIZE_SHIFT) - 1;

	return id >= (pslab->pool_nr - FREE_POOL_OFFSET) ?
			(pslab->pool_nr - FREE_POOL_OFFSET) : id;
}

hidden void add_slab_mem(unsigned long base, size_t size)
{
	int i;
	struct slab_pool *pool;
	struct slab_header *header;

	if (size < SLAB_MIN_SIZE)
		return;

	pool = &pslab->pool[pslab->pool_nr - FREE_POOL_OFFSET - 1];
	if (size <= SLAB_SIZE(pool->size)) {
		if (size < SLAB_SIZE(SLAB_MIN_DATA_SIZE)) {
			return;
		}

		i = size - SLAB_HEADER_SIZE;
		i &= ~(SLAB_MIN_DATA_SIZE - 1);
		if (i < SLAB_MIN_DATA_SIZE)
			return;

		size = i;
		i = slab_pool_id(size);
		pool = &pslab->pool[i];
		header = (struct slab_header *)base;
		header->size = size;
		header->next = NULL;
		add_slab_to_slab_pool(header, pool);
		return;
	}

	/*
	 * the last pool is used to cache pool, if the
	 * slab memory region bigger than 512byte, it will
	 * first used as a cached memory slab
	 */
	pool = &pslab->pool[pslab->pool_nr - CACHE_POOL_OFFSET];
	header = (struct slab_header *)base;
	header->size = size - SLAB_HEADER_SIZE;
	header->next = NULL;
	add_slab_to_slab_pool(header, pool);
}

static int alloc_new_slab_page(size_t size)
{
	void *page;
	size_t npages = PAGE_NR(PAGE_BALIGN(size));

	page = get_pages_unlocked(npages);
	if (!page)
		return -ENOMEM;

	/*
	 * in slab allocator free_pages is ued to count how
	 * many slabs has been allocated out, if the count
	 * is 1, then this block can return back tho the
	 * section
	 */
	pslab->free_size = PAGE_BALIGN(size);
	pslab->slab_free = (unsigned long)page;
	pslab->alloc_pages += npages;

	return 0;
}

static inline struct slab_header *get_slab_from_slab_pool(struct slab_pool *pool)
{
	struct slab_header *header;

	header = pool->head;
	pool->head = header->next;
	header->magic = SLAB_MAGIC;
	pool->nr--;

	return header;
}

static void inline add_slab_to_slab_pool(struct slab_header *header,
		struct slab_pool *pool)
{
	header->next = pool->head;
	pool->head = header;
	pool->nr++;
}

static void *get_slab_from_pool(size_t size)
{
	struct slab_pool *slab_pool;
	struct slab_header *header;
	int id = slab_pool_id(size);

	/* if big slab return directly */
	if (id >= (pslab->pool_nr - FREE_POOL_OFFSET))
		return NULL;

	slab_pool = &pslab->pool[id];
	if (!slab_pool->head)
		return NULL;

	header = get_slab_from_slab_pool(slab_pool);

	return SLAB_HEADER_TO_ADDR(header);
}

static void *get_slab_from_big_pool(size_t size)
{
	struct slab_pool *slab_pool;
	struct slab_header *header, *prev;

	/* small slab size return directly */
	if (slab_pool_id(size) < (pslab->pool_nr - FREE_POOL_OFFSET))
		return NULL;

	slab_pool = &pslab->pool[pslab->pool_nr - FREE_POOL_OFFSET];
	header = prev = slab_pool->head;

	/*
	 * get_slab_from_big_pool will find the slab which its
	 * size is equal to the new request slab's size, this
	 * can allocate the slab which is freed by someone
	 */
	while (header != NULL) {
		if (header->size == size) {
			/* return the header and delete it from the pool */
			if (header == prev)
				slab_pool->head = header->next;
			else
				prev->next = header->next;

			header->magic = SLAB_MAGIC;
			return SLAB_HEADER_TO_ADDR(header);
		} else {
			prev = header;
			header = header->next;
			continue;
		}
	}

	return NULL;
}

static void *get_slab_from_slab_free(size_t size)
{
	struct slab_header *header;
	size_t request_size = SLAB_SIZE(size);

	if (pslab->free_size < request_size)
		return NULL;

	header = (struct slab_header *)pslab->slab_free;
	header->size = size;
	header->magic = SLAB_MAGIC;

	pslab->slab_free += request_size;
	pslab->free_size -= request_size;

	if (pslab->free_size < SLAB_SIZE(SLAB_MIN_DATA_SIZE)) {
		header->size += pslab->free_size;
		pslab->slab_free = 0;
		pslab->free_size = 0;
	}

	return SLAB_HEADER_TO_ADDR(header);
}

static void *get_new_slab(size_t size)
{
	int id;
	struct slab_pool *pool;
	struct slab_header *header;

	if (pslab->free_size >= SLAB_SIZE(SLAB_MIN_DATA_SIZE)) {
		/* left memory if is a big slab push to cache pool */
		id = slab_pool_id(pslab->free_size - SLAB_HEADER_SIZE);
		if (id >= pslab->pool_nr - FREE_POOL_OFFSET)
			id = pslab->pool_nr - CACHE_POOL_OFFSET;
		pool = &pslab->pool[id];

		header = (struct slab_header *)pslab->slab_free;
		memset(header, 0, SLAB_HEADER_SIZE);
		header->size = pslab->free_size - SLAB_HEADER_SIZE;
		header->magic = SLAB_MAGIC;
		add_slab_to_slab_pool(header, pool);

		pslab->free_size = 0;
		pslab->slab_free = 0;
	}

	if (alloc_new_slab_page(size))
		return NULL;

	return get_slab_from_slab_free(size);
}

static void *get_slab_from_cache(size_t size)
{
	struct slab_pool *slab_pool;
	struct slab_header *prev;
	struct slab_header *header;
	struct slab_header *ret = NULL;
	struct slab_header *new;
	uint32_t left_size;
	unsigned long base;

	slab_pool = &pslab->pool[pslab->pool_nr - CACHE_POOL_OFFSET];
	header = slab_pool->head;
	prev = slab_pool->head;

	while (header != NULL) {
		if (header->size < size) {
			prev = header;
			header = header->next;
			continue;
		}

		/*
		 * split the chache slab, the memory will split
		 * from the head of the slab
		 */
		base = (unsigned long)header + SLAB_SIZE(size);
		left_size = header->size - size;

		ret = header;

		/*
		 * check the left size, if the the left size smaller
		 * than SLAB_MIN_DATA_SIZE, drop it
		 */
		if (left_size <= SLAB_SIZE(80)) {
			if (prev == header)
				slab_pool->head = header->next;
			else
				prev->next = header->next;

			add_slab_mem(base, left_size);
		} else {
			new = (struct slab_header *)base;
			new->next = header->next;
			new->size = left_size - SLAB_HEADER_SIZE;

			if (prev == header)
				slab_pool->head = new;
			else
				prev->next = new;
		}

		ret->size = size;
		ret->magic = SLAB_MAGIC;
		break;
	}

	if (ret)
		return SLAB_HEADER_TO_ADDR(ret);

	return NULL;
}

static void *get_big_slab(size_t size)
{
	struct slab_pool *slab_pool;
	struct slab_header *header;
	int id = slab_pool_id(size);

	while (1) {
		slab_pool = &pslab->pool[id];
		if (!slab_pool->head) {
			id++;
			if (id == (pslab->pool_nr - CACHE_POOL_OFFSET))
				return NULL;
		} else {
			break;
		}
	}

	header = (struct slab_header *)get_slab_from_slab_pool(slab_pool);

	return SLAB_HEADER_TO_ADDR(header);
}

typedef void *(*slab_alloc_func)(size_t size);

static slab_alloc_func alloc_func[] = {
	get_slab_from_pool,
	get_slab_from_big_pool,
	get_slab_from_cache,
	get_slab_from_slab_free,
	get_new_slab,
	get_big_slab,
	NULL,
};

/*
 * malloc will re-designed which only allocated the kernel
 * object, such as task process stack and others
 */
void *kmalloc(size_t size)
{
	int i = 0;
	void *ret = NULL;
	slab_alloc_func func;

	if (!kmalloc_has_init) {
		fprintf(stderr, "kmalloc has not inited\n");
		return NULL;
	}

	size = get_slab_alloc_size(size);
	if (size > (heap_pool_end - heap_pool_base))
		return (void *)ENOMEM;

	LOCK(lock);

	while (1) {
		func = alloc_func[i];
		if (!func)
			break;

		ret = func(size);
		if (ret)
			break;
		i++;
	}

	UNLOCK(lock);

	return ret;
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
	int id;
	struct slab_header *header;
	struct slab_pool *slab_pool;

	if (!addr)
		return;

	header = ADDR_TO_SLAB_HEADER(addr);
	if (header->magic != SLAB_MAGIC) {
		return;
	}

	LOCK(lock);
	/* big slab will default push to free cache pool */
	id = slab_pool_id(header->size);
	slab_pool = &pslab->pool[id];
	add_slab_to_slab_pool(header, slab_pool);
	UNLOCK(lock);
}

static void slab_init(void)
{
	memset(pslab, 0, sizeof(struct slab));
	pslab->pool = slab_pool;
	pslab->pool_nr = sizeof(slab_pool) / sizeof(slab_pool[0]);
}

hidden int kmalloc_init(unsigned long base, unsigned long end)
{
	size_t page_size;
	size_t bitmap_size;
	size_t meta_size;

	if ((end < base) || !IS_PAGE_ALIGN(base) || !IS_PAGE_ALIGN(end)) {
		fprintf(stderr, "invalid heap region 0x%lx 0x%lx\n", base, end);
		return -EINVAL;
	}

	/*
	 * caculate how many meta memory size is needed for
	 * allocation management.
	 *
	 * meta_size = struct(page) * nr_page + page bitmap size.
	 */
	page_size = (end - base) >> PAGE_SHIFT;
	bitmap_size = BITMAP_SIZE(page_size);
	page_size = BALIGN(page_size * sizeof(struct page), 16);
	meta_size = PAGE_BALIGN(page_size + bitmap_size);
	memset((void *)base, 0, meta_size);

	/*
	 * caculate the real free memory that the process
	 * can be used.
	 */
	pages = (struct page *)base;
	bitmap = (unsigned long *)(base + page_size);
	heap_pool_base = (base + meta_size);
	heap_pool_end = end;
	page_nr = (end - heap_pool_base) >> PAGE_SHIFT;

	slab_init();
	kmalloc_has_init = 1;

	return 0;
}
