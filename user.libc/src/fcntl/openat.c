#include <fcntl.h>
#include <stdarg.h>
#include "syscall.h"
#include <string.h>
#include "stdio_impl.h"

#include <minos/proto.h>
#include <minos/kobject.h>

static int __openat(int fd, const char *filename, int flags, mode_t mode)
{
	struct proto proto;

	proto.proto_id = PROTO_OPENAT;
	proto.openat.flags = flags;
	proto.openat.mode = mode;

	return kobject_write(fd, &proto, sizeof(struct proto),
			(void *)filename, strlen(filename), -1);
}

int openat(int fd, const char *filename, int flags, ...)
{
	mode_t mode = 0;
	int handle;
	FILE *f;

	if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}

	handle = __openat(fd, filename, flags | O_LARGEFILE, mode);
	if (handle <= 0)
		return handle;

	f = __fdopen(fd, mode);
	if (f)
		return f->fd;

	kobject_close(handle);

	return -ENOMEM;
}

weak_alias(openat, openat64);
