#include "stdio_impl.h"
#include <sys/ioctl.h>

size_t __stdout_write(FILE *f, const unsigned char *buf, size_t len)
{
	return syscall(SYS_kobject_send, f->fd, buf, len, NULL, 0, 0, 0);
}
