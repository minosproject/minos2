#include <unistd.h>
#include <fcntl.h>
#include "syscall.h"
#include <string.h>

#include <minos/proto.h>
#include <minos/kobject.h>
#include "libc.h"

int access(const char *filename, int amode)
{
	struct proto proto;

	if (strcmp(".", filename) == 0)
		return -EINVAL;
	if (strcmp("..", filename) == 0)
		return -EINVAL;
	if (filename[strlen(filename) - 1] == '/')
		return -EINVAL;

	/*
	 * currently only support Absolute path, TBD
	 */
	if (filename[0] != '/')
		return -EINVAL;

	proto.proto_id = PROTO_ACCESS;
	proto.access.amode = amode;

	return sys_send_proto_with_data(libc.rootfs_handle,
			&proto, (void *)filename, strlen(filename), -1);
}
