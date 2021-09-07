/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"
#include <sys/epoll.h>

#include <minos/proto.h>
#include <minos/kobject.h>

#define MODE_ANY 0
#define MODE_STRING 1
#define MODE_EQUAL 2

static int __kobject_read_proto(int handle, struct proto *proto, char *extra,
		size_t size, uint32_t timeout, int mode)
{
	size_t dsize, esize;
	long token;
	int success;

	token = kobject_read(handle, proto, sizeof(struct proto),
			&dsize, extra, size, &esize, timeout);
	if (token < 0)
		return (int)token;

	switch (mode) {
	case MODE_STRING:
		success = (esize < size);
		break;
	case MODE_EQUAL:
		success = (esize == size);
		break;
	default:
		success = (esize <= size);
		break;
	}

	if (!success) {
		kobject_reply(handle, token, -EINVAL, 0, 0);
		return -EINVAL;
	}

	proto->token = token;
	if (mode == MODE_STRING)
		extra[esize] = 0;

	return 0;
}

int kobject_read_proto_with_string(int handle, struct proto *proto,
		char *extra, size_t size, uint32_t timeout)
{
	return __kobject_read_proto(handle, proto, extra, size, timeout, MODE_STRING);
}

int kobject_read_proto(int handle, struct proto *proto,
		char *extra, size_t size, uint32_t timeout)
{
	return __kobject_read_proto(handle, proto, extra, size, timeout, MODE_EQUAL);
}

void i_am_ok(void)
{
	struct proto proto;

	proto.proto_id = PROTO_IAMOK;
	kobject_write(0, &proto, PROTO_SIZE, NULL, 0, -1);
}
