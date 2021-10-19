#include <unistd.h>
#include "syscall.h"
#include <string.h>
#include "stdio_impl.h"

#include <minos/proto.h>
#include <minos/kobject.h>

ssize_t read(int fd, void *buf, size_t count)
{
	FILE *file;

	file = __ofl_get_file(fd);
	if (!file)
		return -ENOENT;

	return fread(buf, count, 1, file);
}
