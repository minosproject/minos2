/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"
#include <sys/epoll.h>
#include <minos/kobject.h>
#include <minos/proto.h>

int sys_proccnt(void)
{
	struct proto proto = {
		.proto_id = PROTO_PROCCNT,
	};

	return sys_send_proto(0, &proto);
}

int sys_procinfo_handle(void)
{
	struct proto proto = {
		.proto_id = PROTO_PROCINFO,
	};

	return sys_send_proto(0, &proto);
}

int sys_taskstat_handle(void)
{
	struct proto proto = {
		.proto_id = PROTO_TASKSTAT,
	};

	return sys_send_proto(0, &proto);
}
