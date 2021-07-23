#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"

int kobject_connect(char *path, right_t right)
{
	return syscall(SYS_kobject_connect, path, right);
}

int kobject_close(handle_t handle)
{
	return syscall(SYS_kobject_open, handle);
}

long kobject_listen(handle_t dst, handle_t src, int event,
		unsigned long data)
{
	return syscall(SYS_kobject_listen, dst, src, event, data);
}

handle_t kobject_create(char *name, int type, int right,
		unsigned long flags, unsigned long data)
{
	return syscall(SYS_kobject_create, name, type,
			right, flags, data);
}

ssize_t kobject_read(handle_t handle, void *data, size_t data_size,
		void *extra, size_t extra_size, uint32_t timeout)
{
	return syscall(SYS_kobject_recv, handle, data, data_size,
			extra, extra_size, timeout);
}

ssize_t kobject_write(handle_t handle, void *data, size_t data_size,
		void *extra, size_t extra_size, uint32_t timeout)
{
	return syscall(SYS_kobject_send, handle, data, data_size,
			extra, extra_size, timeout);
}

int kobject_reply(handle_t handle, long token, int err_code)
{
	return syscall(SYS_kobject_reply, token, err_code);
}

void *kobject_mmap(handle_t handle)
{
	return (void *)syscall(SYS_kobject_mmap, handle);
}

int kobject_unmap(handle_t handle)
{
	return syscall(SYS_kobject_munmap, handle);
}

long kobject_ctl(handle_t handle, int action, unsigned long data)
{
	return syscall(SYS_kobject_ctl, handle, action, data);
}

int kobject_open(handle_t handle)
{
	return syscall(SYS_kobject_open, handle);
}
