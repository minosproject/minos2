/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
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

#include <minos/minos.h>
#include <minos/of.h>
#include <minos/mm.h>

struct io_block {
	void *iobase;
	int free;
	struct io_block *next;
	unsigned long bitmap[BITS_TO_LONGS(PAGES_PER_BLOCK)];
};

static struct io_block *io_block_head;
static DEFINE_SPIN_LOCK(iob_lock);

static void *get_io_pages_from_block(struct io_block *iob, int pages)
{
	int start;

	start = bitmap_find_next_zero_area(iob->bitmap,
			PAGES_PER_BLOCK, 0, pages, 0);
	if (start >= PAGES_PER_BLOCK)
		return NULL;

	bitmap_set(iob->bitmap, start, pages);

	return (iob->iobase + (start << PAGE_SHIFT));
}

static void *alloc_new_io_block(int pages)
{
	void *base;
	struct io_block *iob;

	base = get_free_block(GFP_HUGE_IO);
	if (!base)
		return NULL;

	iob = malloc(sizeof(struct io_block));
	if (!iob) {
		free(base);
		return NULL;
	}

	memset(iob, 0, sizeof(struct io_block));
	iob->iobase = base;
	iob->free = PAGES_PER_BLOCK;

	base = get_io_pages_from_block(iob, pages);
	ASSERT(base != NULL);

	/*
	 * add new io block to the global list.
	 */
	iob->next = io_block_head;
	io_block_head = iob;

	return base;
}

void *get_io_pages(int pages)
{
	struct io_block *bhead = io_block_head;
	void *base = NULL;

	if ((pages == 0) || (pages > PAGES_PER_BLOCK)) {
		pr_err("io pages can not beyond %d\n", PAGES_PER_BLOCK);
		return NULL;
	}

	spin_lock(&iob_lock);

	while (bhead) {
		if (bhead->free < pages)
			continue;
		
		base = get_io_pages_from_block(bhead, pages);
		if (base)
			break;
	}

	if (!base)
		base = alloc_new_io_block(pages);

	spin_unlock(&iob_lock);

	return base;
}

void free_io_pages(void *addr)
{

}
