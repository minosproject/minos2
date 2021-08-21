/*
 * Copyright (c) 2021 Min Le (lemin9538@163.com)
 * Copyright (c) 2021 上海网返科技
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <minos/list.h>
#include <minos/debug.h>
#include <minos/kmalloc.h>
#include <minos/compiler.h>
#include <minos/kobject.h>

#include <libminos/vfs.h>
#include <libminos/file.h>
#include <libminos/blkdev.h>
#include "fs.h"

struct file *vfs_open(struct partition *part, char *path, int flags, int mode)
{
	struct file *file;
	struct fnode *fnode;
	int ret = 0;

	ret = fs_open(part->sb, path, &fnode);
	if (ret)
		return NULL;

	file = create_file(flags, mode);
	if (!file)
		return NULL;

	file->fnode = fnode;
	part->open_file = file;
	
	return file;
}

static struct file *handle_to_file(struct partition *part, int handle)
{
	struct file *head = part->open_file;

	while (head) {
		if (head->handle == handle)
			return head;
		head = head->next;
	}

	return NULL;
}

ssize_t vfs_read(struct partition *part, int handle, size_t size)
{
	struct file *file = handle_to_file(part, handle);
	ssize_t ret;

	if (!file)
		return -ENOENT;
	if (size > file->sbuf_size)
		return -E2BIG;

	ret = part->fs->read(file->fnode, file->sbuf, size, file->offset);
	if (ret < 0)
		return ret;

	file->offset += size;
	return ret;
}

ssize_t vfs_write(struct partition *part, int handle, size_t size)
{
	return 0;
}

int vfs_init(void)
{
	hidden extern struct filesystem fat_fs;

	register_filesystem(&fat_fs);

	return 0;
}
