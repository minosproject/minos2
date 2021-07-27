#include "stdio_impl.h"
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <minos/kobject.h>
#include <minos/proto.h>

#define FILE_PATH_MIN 4

/*
 * fopen("c:/home/minos/1.txt")
 */
int __sys_open(const char *restrict filename, int flags, int mode)
{
	int len = strlen(filename);
	int handle, fd;
	char path[2];
	struct proto proto;

	if ((len >= FILENAME_MAX) || isalpha(filename[0]) ||
			(filename[1] != ':') || (filename[2] != '/'))
		return -EINVAL;

	/*
	 * connect to the target service using kobject connect
	 * then the process can write data to the target server.
	 */
	path[0] = filename[0];
	path[1] = 0;
	handle = kobject_connect(path, KOBJ_RIGHT_WRITE);
	if (handle < 0)
		return handle;

	proto.proto_id = PROTO_OPEN;
	proto.open.flags = flags;
	proto.open.mode = mode;

	fd = kobject_write(handle, &proto, sizeof(struct proto),
			(char *)filename, len + 1, -1);
	kobject_close(handle);

	return fd;
}

FILE *fopen(const char *restrict filename, const char *restrict mode)
{
	FILE *f;
	int fd;
	int flags;

	/* Check for valid initial mode character */
	if (!strchr("rwa", *mode)) {
		errno = EINVAL;
		return 0;
	}

	/* Compute the flags to pass to open() */
	flags = __fmodeflags(mode);

	fd = __sys_open(filename, flags, 0666);
	if (fd < 0) return 0;

#if 0
	if (flags & O_CLOEXEC)
		__syscall(SYS_fcntl, fd, F_SETFD, FD_CLOEXEC);
#endif

	f = __fdopen(fd, mode);
	if (f) return f;

	kobject_close(fd);
	return 0;
}

weak_alias(fopen, fopen64);
