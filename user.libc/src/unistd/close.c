#include <unistd.h>
#include <errno.h>
#include "syscall.h"
#include "stdio_impl.h"

int close(int fd)
{
	return fclose_fd(fd);
}
