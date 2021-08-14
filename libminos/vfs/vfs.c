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
#include <libminos/blkdev.h>
#include "fs.h"

#define FILE_RIGHT \
	(KOBJ_RIGHT_RW | KOBJ_RIGHT_GRANT | KOBJ_RIGHT_MMAP)
#define FILE_REQ_RIGHT \
	(KOBJ_RIGHT_READ | KOBJ_RIGHT_MMAP)

struct file *vfs_open(struct partition *part, char *path, int flags, int mode)
{
	struct endpoint_create_arg args = {
		.mode = EP_MODE_NORMAL,
		.shmem_size = PAGE_SIZE,
	};
	struct file *file;
	struct fnode *fnode;
	int handle;
	int ret = 0;

	ret = fs_open(part->sb, path, &fnode);
	if (ret)
		return NULL;

	// check the mode, TBD.
	file = kzalloc(sizeof(struct file));
	if (!file)
		return NULL;

	handle = kobject_create(KOBJ_TYPE_ENDPOINT,
			FILE_RIGHT, FILE_REQ_RIGHT, (unsigned long)&args);
	if (handle < 0) {
		kfree(file);
		return NULL;
	}

	file->handle = handle;
	file->sbuf = kobject_mmap(handle);
	if (file->sbuf == (char *)-1) {
		kobject_close(handle);
		kfree(file);
		return NULL;
	}

	file->offset = 0;
	file->f_flags = 0;
	file->f_mode = 0;
	file->offset = 0;
	file->fnode = fnode;
	file->next = part->open_file;
	file->handle = handle;
	file->sbuf_size = PAGE_SIZE;
	file->mmap_mode = 0;
	part->open_file = file;
	
err_map_file:
	kfree(file);
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
