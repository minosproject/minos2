/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <assert.h>

#include <minos/kobject.h>
#include <minos/types.h>
#include <minos/debug.h>
#include <minos/list.h>
#include <minos/procinfo.h>
#include <minos/proto.h>

#include <pangu/kmalloc.h>
#include <pangu/proc.h>
#include <pangu/mm.h>
#include <pangu/bootarg.h>

static uint32_t proc_cnt;
static unsigned char *bitmap;
static int proc_bytes;

static int ktask_stat_handle;

int8_t const ffs_one_table[256] = { 
        -1, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, /* 0x00 to 0x0F */
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, /* 0x10 to 0x1F */
        5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, /* 0x20 to 0x2F */
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, /* 0x30 to 0x3F */
        6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, /* 0x40 to 0x4F */
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, /* 0x50 to 0x5F */
        5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, /* 0x60 to 0x6F */
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, /* 0x70 to 0x7F */
        7, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, /* 0x80 to 0x8F */
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, /* 0x90 to 0x9F */
        5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, /* 0xA0 to 0xAF */
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, /* 0xB0 to 0xBF */
        6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, /* 0xC0 to 0xCF */
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, /* 0xD0 to 0xDF */
        5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, /* 0xE0 to 0xEF */
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0  /* 0xF0 to 0xFF */
};

int alloc_pid(void)
{
	int i, j;

	for (i = 0; i < proc_bytes; i++) {
		if (bitmap[i] == 0)
			continue;

		j = ffs_one_table[bitmap[i]];
		bitmap[i] &= ~(1 << j);

		return (i * 8 + j);
	}

	return -1;
}

void procinfo_init(int max_proc, int ktask_handle)
{
	proc_cnt = max_proc;
	ktask_stat_handle = ktask_handle;
	proc_bytes = proc_cnt / 8;

	bitmap = kmalloc(proc_bytes);
	assert(bitmap != NULL);
	memset(bitmap, 0xff, proc_bytes);

	/*
	 * PID 0 is for kernel.
	 */
	assert(alloc_pid() == 0);
}

void release_pid(int pid)
{
	int i = pid / 8;
	int j = pid % 8;

	bitmap[i] |= (1 << j);
}

long pangu_taskstat(struct process *proc, struct proto *proto, void *data)
{
	return kobject_reply_handle(proc->proc_handle,
			proto->token, ktask_stat_handle, KR_RM);
}

long pangu_proccnt(struct process *proc, struct proto *proto, void *data)
{
	return kobject_reply_errcode(proc->proc_handle, proto->token, proc_cnt);
}
