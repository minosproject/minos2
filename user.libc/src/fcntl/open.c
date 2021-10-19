#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include "syscall.h"
#include "stdio_impl.h"

#include <minos/kobject.h>

int open(const char *filename, int flags, ...)
{
	mode_t mode = 0;
	FILE *filep;
	int fd;

	if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}

	fd = __sys_open(filename, flags, mode);
	if (fd <= 0)
		return fd;

	filep = __fdopen(fd, flags);
	if (filep)
		return fd;

	kobject_close(fd);

	return -ENOMEM;
}

weak_alias(open, open64);
