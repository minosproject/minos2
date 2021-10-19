/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

#include "stdio_impl.h"
#include <sys/epoll.h>
#include <minos/kobject.h>
#include <minos/proto.h>
#include <minos/types.h>

int __mprotect(void *addr, size_t len, int prot)
{
        size_t start, end;
	struct proto proto;

        start = (size_t)addr & - PAGE_SIZE;
        end = (size_t)((char *)addr + len + PAGE_SIZE-1) & -PAGE_SIZE;

	proto.proto_id = PROTO_MPROTECT;
	proto.mprotect.addr = (void *)start;
	proto.mprotect.len = end - start;
	proto.mprotect.prot = prot;

	return 0;
}

weak_alias(__mprotect, mprotect);
