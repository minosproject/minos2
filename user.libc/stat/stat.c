#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "stdio_impl.h"
#include <minos/kobject.h>
#include <minos/proto.h>

int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
	return -EOPNOTSUPP;
}

int fstat(int fd, struct stat *statbuf)
{
	struct proto proto;
	int handle;
	int ret;

	if (fd <= 0)
		return -EINVAL;

	proto.proto_id = PROTO_STAT;
	handle = sys_send_proto(fd, &proto);
	if (handle <= 0)
		return handle;

	ret = kobject_read_simple(handle, statbuf, sizeof(struct stat), 0);
	kobject_close(handle);

	return ret;
}

int stat(const char *pathname, struct stat *statbuf)
{
	return -EOPNOTSUPP;
}

int lstat(const char *pathname, struct stat *statbuf)
{
	return stat(pathname, statbuf);
}
