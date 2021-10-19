#include <stdio.h>
#include <unistd.h>
#include "syscall.h"
#include "stdio_impl.h"

ssize_t write(int fd, const void *buf, size_t count)
{
	FILE *file;

	file = __ofl_get_file(fd);
	if (!file)
		return -ENOENT;

	return fwrite(buf, count, 1, file);
}
