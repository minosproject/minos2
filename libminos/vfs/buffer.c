/*
 * Copyright (c) 2021 Min Le (lemin9538@163.com)
 * Copyright (c) 2021 上海网返科技
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <dirent.h>

#include <minos/list.h>
#include <minos/debug.h>
#include <minos/compiler.h>
#include <minos/kmalloc.h>

#include <libminos/vfs.h>

#include "buffer.h"

static struct buffer_head *get_hash_table(struct super_block *sb, unsigned long block)
{
	int id = block & 10;
	struct buffer_head *bh;

	list_for_each_entry(bh, &sb->buffer_hash_lists[id], list) {
		if (bh->b_blocknr == block)
			return bh;
	}

	return NULL;
}

static inline void put_last_lru(struct super_block *sb,
		struct buffer_head *bh, unsigned long block)
{
	/*
	 * TBD
	 */
	list_del(&bh->lru_list);
	list_add_tail(&sb->buffer_hash_lists[block % 10], &bh->lru_list);
}

static inline void refill_buffer_head(struct super_block *sb,
		struct buffer_head *bh, unsigned long block)
{
	list_del(&bh->list);
	bh->b_blocknr = block;
	bh->b_state = 0;
	list_add_tail(&sb->buffer_hash_lists[block % 10], &bh->list);
}

struct buffer_head *get_block(struct super_block *sb,
		unsigned long block)
{
	struct buffer_head *bh;

	/*
	 * get the buffer_head from hash table which aready
	 * contain data.
	 */
	bh = get_hash_table(sb, block);
	if (bh) {
		if (!buffer_dirty(bh)) {
			if (buffer_uptodate(bh))
				put_last_lru(sb, bh, block);
		}
		set_bit(BH_Touched, &bh->b_state);
		return bh;
	}

	/*
	 * get from free list
	 */
	if (!is_list_empty(&sb->buffer_free_list)) {
		bh = list_first_entry(&sb->buffer_free_list, struct buffer_head, list);
		list_add_tail(&sb->buffer_lru_list, &bh->lru_list);
		refill_buffer_head(sb, bh, block);
		return bh;
	}

	/*
	 * get from the head of lru list.
	 */
	bh = list_first_entry(&sb->buffer_lru_list, struct buffer_head, list);
	refill_buffer_head(sb, bh, block);
	put_last_lru(sb, bh, block);

	return bh;
}

void buffer_head_init(struct super_block *sb)
{
	int blocks_per_page = PAGE_SIZE / sb->block_size;
	struct buffer_head *bh;
	char *data;
	int i, j;

	init_list(&sb->buffer_free_list);
	init_list(&sb->buffer_lru_list);
	for (i = 0; i < NR_HASH_LIST; i++)
		init_list(&sb->buffer_hash_lists[i]);

	for (i = 0; i < 128; i++) {
		data = get_pages(1);
		if (!data)
			return;

		for (j = 0; j < blocks_per_page; j++) {
			bh = kzalloc(sizeof(struct buffer_head));
			if (!bh)
				return;

			bh->data = data;
			bh->data = data + j * sb->block_size;
			list_add(&sb->buffer_free_list, &bh->list);
		}
	}
}
