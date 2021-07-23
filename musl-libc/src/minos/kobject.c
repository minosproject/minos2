#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"

int kobject_connect(char *path, int right)
{
	return syscall(SYS_kobject_connect, path, right);
}

int kobject_close(int handle)
{
	return syscall(SYS_kobject_open, handle);
}

long kobject_listen(int dst, int src, int event, unsigned long data)
{
	return syscall(SYS_kobject_listen, dst, src, event, data);
}

int kobject_create(char *name, int type, int right,
		unsigned long flags, unsigned long data)
{
	return syscall(SYS_kobject_create, name, type,
			right, flags, data);
}

ssize_t kobject_read(int handle, void *data, size_t data_size,
		void *extra, size_t extra_size, uint32_t timeout)
{
	return syscall(SYS_kobject_recv, handle, data, data_size,
			extra, extra_size, timeout);
}

ssize_t kobject_write(int handle, void *data, size_t data_size,
		void *extra, size_t extra_size, uint32_t timeout)
{
	return syscall(SYS_kobject_send, handle, data, data_size,
			extra, extra_size, timeout);
}

int kobject_reply(int handle, long token, int err_code)
{
	return syscall(SYS_kobject_reply, token, err_code);
}

void *kobject_mmap(int handle)
{
	return (void *)syscall(SYS_kobject_mmap, handle);
}

int kobject_unmap(int handle)
{
	return syscall(SYS_kobject_munmap, handle);
}

long kobject_ctl(int handle, int action, unsigned long data)
{
	return syscall(SYS_kobject_ctl, handle, action, data);
}

int kobject_open(int handle)
{
	return syscall(SYS_kobject_open, handle);
}
