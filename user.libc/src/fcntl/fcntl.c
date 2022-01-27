#define _GNU_SOURCE
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include "syscall.h"

int fcntl(int fd, int cmd, ...)
{
	return 0;
}
