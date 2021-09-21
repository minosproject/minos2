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
#include <minos/compiler.h>
#include <minos/kobject.h>
#include <minos/types.h>

#include <vfs/file.h>

#define FILE_RIGHT \
	(KOBJ_RIGHT_RW | KOBJ_RIGHT_GRANT | KOBJ_RIGHT_MMAP)
#define FILE_REQ_RIGHT \
	(KOBJ_RIGHT_READ | KOBJ_RIGHT_MMAP)

struct file *create_file(int flags, int mode)
{
	struct file *f;
	int handle;
	void *addr;

	handle = kobject_create_endpoint(FILE_RIGHT, FILE_REQ_RIGHT, PAGE_SIZE);
	if (handle <= 0)
		return NULL;

	addr = kobject_mmap(handle);
	if (addr == (void *)-1) {
		kobject_close(handle);
		return NULL;
	}

	f = malloc(sizeof(struct file));
	if (f == NULL) {
		kobject_close(handle);
		return NULL;
	}

	f->f_mode = mode;
	f->f_flags = flags;
	f->sbuf_size = PAGE_SIZE;
	f->sbuf = addr;
	f->handle = handle;
	f->offset = 0;
	f->pdata = 0;

	return f;
}

void release_file(struct file *file)
{
	if (!file)
		return;

	kobject_munmap(file->handle);
	kobject_close(file->handle);
	free(file);
}
