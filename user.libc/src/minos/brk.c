/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"
#include <sys/epoll.h>
#include <minos/kobject.h>
#include <minos/proto.h>

uintptr_t __brk(uintptr_t ptr)
{
	struct proto proto;

	proto.proto_id = PROTO_BRK;
	proto.brk.addr = (void *)ptr;

	return (uintptr_t)__syscall_ret(kobject_write(0, &proto,
			sizeof(struct proto), NULL, 0, -1));
}
