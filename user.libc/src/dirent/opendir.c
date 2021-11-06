#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include "__dirent.h"
#include "syscall.h"
#include "stdio_impl.h"

#include <minos/kobject.h>

static DIR *__dirfd_open(int fd)
{
	DIR *dir;

	dir = calloc(1, sizeof *dir);
	if (!dir)
		goto out;

	dir->buf_size = BUFSIZ;
	dir->fd = fd;
	if (kobject_mmap(fd, &dir->buf, NULL))
		goto out_free;

	return dir;

out_free:
	free(dir);
out:
	kobject_close(fd);
	return NULL;
}

DIR *opendir(const char *name)
{
	int fd;

	if ((fd = __sys_open(name, O_RDONLY|O_DIRECTORY|O_CLOEXEC, 0)) < 0)
		return 0;

	return __dirfd_open(fd);
}
