/*
 * Copyright (c) 2021 Min Le (lemin9538@163.com)
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <minos/list.h>
#include <minos/debug.h>
#include <minos/kmalloc.h>
#include <minos/compiler.h>

#include <libminos/fs.h>
#include <libminos/blkdev.h>

int vfs_open(struct partition *part, char *path, handle_t fd,
		size_t sbuf_size, int mode)
{
	struct file *file;
	struct fnode *fnode;
	handle_t handle;
	int ret = 0;

	ret = fs_open(part->sb, path, &fnode);
	if (ret)
		return ret;

	// check the mode, TBD.
	file = kzalloc(sizeof(struct file));
	if (!file)
		return -ENOMEM;

#if 0
	/*
	 * mmap the handle to our space.
	 */
	file->sbuf = mmap(NULL, sbuf_size, fd, PROT_READ | PORT_WRITE, 0, fd);
	if (!file->sbuf == (void *)-1) {
		ret = -EFAULT;
		goto err_map_file;
	}
#endif

	file->offset = 0;
	file->f_flags = 0;
	file->f_mode = 0;
	file->offset = 0;
	file->fnode = fnode;
	file->next = part->open_file;
	file->handle = fd;
	file->sbuf_size = sbuf_size;
	file->mmap_mode = 0;
	part->open_file = file;
	
err_map_file:
	kfree(file);
	return ret;
}

static struct file *handle_to_file(struct partition *part, handle_t handle)
{
	struct file *head = part->open_file;

	while (head) {
		if (head->handle == handle)
			return head;
		head = head->next;
	}

	return NULL;
}

ssize_t vfs_read(struct partition *part, handle_t handle, size_t size)
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

ssize_t vfs_write(struct partition *part, handle_t handle, size_t size)
{
	return 0;
}

int vfs_init(void)
{
	hidden extern struct filesystem fat_fs;

	register_filesystem(&fat_fs);

	return 0;
}
