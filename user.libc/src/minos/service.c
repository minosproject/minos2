#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "stdio_impl.h"
#include <minos/kobject.h>
#include <minos/proto.h>
#include "libc.h"

int register_service(const char *src, const char *target, int type, int flags)
{
	char string[FILENAME_MAX];
	struct proto proto;
	char *buf = string;
	int len, handle;

	len = strlen(src) + strlen(target) + 2;
	if (len >= FILENAME_MAX)
		return -ENAMETOOLONG;

	strcpy(buf, src);
	buf += strlen(src) + 1;
	strcpy(buf, target);

	proto.proto_id = PROTO_REGISTER_SERVICE;
	proto.register_service.type = type;
	proto.register_service.flags = flags;
	proto.register_service.source_off = 0;
	proto.register_service.target_off = strlen(src) + 1;

	handle = kobject_write(libc.rootfs_handle, &proto,
			sizeof(struct proto), string, len, -1);

	return handle;
}

int unregister_service(int fd)
{
	return kobject_close(fd);
}
