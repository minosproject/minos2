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
#include <minos/kmalloc.h>
#include <minos/compiler.h>
#include <minos/kobject.h>

#include <vfs/vfs.h>
#include <vfs/file.h>
#include <vfs/blkdev.h>

#include "buffer.h"

#define MAX_FS	32

static struct filesystem *fses[MAX_FS];
static int fs_index;

struct filesystem *lookup_filesystem(unsigned char type)
{
	struct filesystem *fs;
	int i;

	for (i = 0; fses[i] != NULL; i++) {
		fs = fses[i];
		if (fs->match && fs->match(type, NULL))
			return fs;
	}

	return NULL;
}

int register_filesystem(struct filesystem *fs)
{
	if (!fs || !fs->match || !fs->read_super)
		return -EINVAL;

	fses[fs_index++] = fs;
	return 0;
}

static struct fnode *fs_find_file_in_opened(struct fnode *fnode, char *name)
{
	struct fnode *node;

	list_for_each_entry(node, &fnode->child, list) {
		if (strcmp(name, node->name) == 0)
			return node;
	}

	return NULL;
}

static int fs_open(struct fnode *parent, char *path, struct fnode **out)
{
	struct super_block *sb = parent->sb;
	struct fnode *cur = parent;
	char *pathrem, *end, *name;
	struct fnode *next;
	int ret = 0;

	*out = NULL;
	name = libc_malloc(FILENAME_MAX);
	if (!name)
		return -ENOMEM;

	for (;;) {
		while (*pathrem == '/')
			pathrem++;

		if (*pathrem == '\0') {
			*out = cur;
			goto out;
		}

		if (cur->type != DT_DIR) {
			ret = -ENOTDIR;
			goto out;
		}

		end = strchrnul(pathrem, '/');
		if (end - pathrem >= FILENAME_MAX) {
			ret = -ENAMETOOLONG;
			goto out;
		}

		/*
		 * first find the request fnode in the opened
		 * file list. then find the fnode from the storage.
		 */
		strlcpy(name, pathrem, end - pathrem + 1);
		next = fs_find_file_in_opened(cur, name);
		if (!next) {
			ret = sb->fs->lookup(cur, name, &next);
			if (ret)
				ret = -ENOENT;
		}

		strcpy(next->name, name);
		cur = next;
		pathrem = end;
	}

out:
	kfree(name);
	return ret;
}

struct file *vfs_open(struct file *parent, char *path, int flags, int mode)
{
	struct fnode *fnode;
	struct file *file;
	int ret = 0;

	ret = fs_open(parent->fnode, path, &fnode);
	if (ret)
		return NULL;

	file = create_file(flags, mode);
	if (!file)
		return NULL;

	file->fnode = fnode;
	
	return file;
}

ssize_t vfs_read(struct file *file, void *buf, size_t size)
{
	ssize_t ret;

	if (size > file->sbuf_size)
		return -E2BIG;

	ret = file->fnode->sb->fs->read(file->fnode, file->sbuf, size, file->offset);
	if (ret < 0)
		return ret;

	file->offset += size;
	return ret;
}

ssize_t vfs_write(struct file *file, void *buf, size_t size)
{
	return 0;
}

int vfs_read_super(struct partition *part, struct filesystem *fs)
{
	struct super_block *sb;

	sb = fs->read_super(part, fs);
	if (!sb)
		return -ENOMEM;

	sb->partition = part;
	sb->fs = fs;
	part->sb = sb;
	buffer_head_init(sb);

	return 0;
}

int vfs_init(void)
{
	hidden extern struct filesystem fat_fs;

	register_filesystem(&fat_fs);

	return 0;
}