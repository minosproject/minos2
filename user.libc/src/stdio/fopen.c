#include "stdio_impl.h"
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include "libc.h"

#include <minos/kobject.h>
#include <minos/proto.h>

#define FILE_PATH_MIN 4

int __sys_open(const char *restrict filename, int flags, int mode)
{
	int len = strlen(filename);
	struct proto proto;

	if ((len >= FILENAME_MAX) || (filename[0] != '/'))
		return -EINVAL;

	if (libc.rootfs_handle <= 0)
		return -ENOENT;

	proto.proto_id = PROTO_OPEN;
	proto.open.flags = flags;
	proto.open.mode = mode;

	return kobject_write(libc.rootfs_handle, &proto, sizeof(struct proto),
			(char *)filename, len, 5000);
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

	fd = __sys_open(filename, flags, 0);
	if (fd < 0)
		return 0;

#if 0
	if (flags & O_CLOEXEC)
		__syscall(SYS_fcntl, fd, F_SETFD, FD_CLOEXEC);
#endif

	f = __fdopen(fd, flags);
	if (f)
		return f;

	kobject_close(fd);

	return 0;
}

weak_alias(fopen, fopen64);
