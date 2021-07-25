/*
 * Copyright (c) 2021 - 2021 Min Le (lemin9538@163.com)
 */

#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <minos/list.h>
#include <minos/debug.h>
#include <minos/kmalloc.h>

#include <libminos/vfs.h>
#include <libminos/blkdev.h>
#include "fs.h"

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
	if (!fs || !fs->match || !fs->create_super_block ||
			!fs->find_file || !fs->read)
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

int fs_open(struct super_block *sb, char *path, struct fnode **out)
{
	struct fnode *cur = sb->root_fnode;
	struct partition *part = sb->partition;
	char *pathrem, *end, *name;
	int ret = 0;
	struct fnode *next;

	/*
	 * currently only support Absolute path.
	 */
	if ((path[0] != '/') || (path[0] == 0)) {
		pr_err("Only support absolute path\n");
		return -EINVAL;
	}

	*out = NULL;
	pathrem = path + 1;
	name = kmalloc(FILENAME_MAX);
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
			next = part->fs->find_file(cur, name);
			if (!next) {
				ret = -ENOENT;
				goto out;
			}
		}
		
		strcpy(next->name, name);
		cur = next;
		pathrem = end;
	}

out:
	kfree(name);
	return ret;
}

int fs_read(struct fnode *fnode, char *buf, size_t size, off_t offset)
{
	long ret;

	ret = fnode->partition->fs->read(fnode, buf, size, offset);
	if (ret < 0)
		return ret;

	fnode->location = offset + ret;
	return ret;
}

int fs_write(struct fnode *fnode, char *buf, size_t size, off_t offset)
{
	long ret;

	ret = fnode->partition->fs->write(fnode, buf, size, offset);
	if (ret != size)
		return -EIO;

	fnode->location = offset + size;
	return ret;
}
