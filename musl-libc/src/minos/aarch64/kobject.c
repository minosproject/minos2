#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"
#include "aarch64_svc.h"

int kobject_connect(char *path, int right)
{
	return syscall(SYS_kobject_connect, path, right);
}

int kobject_close(int handle)
{
	return syscall(SYS_kobject_open, handle);
}

int kobject_create(char *name, int type, int right,
		int right_req, unsigned long data)
{
	return syscall(SYS_kobject_create, name, type,
			right, right_req, data);
}

/*
 * <  0 : failed
 * >= 0 : the token or other things for read/write
 */
long kobject_read(int handle, void *data, size_t data_size,
		size_t *actual_data, void *extra, size_t extra_size,
		size_t *actual_extra, uint32_t timeout)
{
	struct aarch64_svc_res res;
	long ret;

	aarch64_svc_call((unsigned long)handle, (unsigned long)data,
			(unsigned long)data_size, (unsigned long)extra,
			(unsigned long)extra_size, (unsigned long)timeout, 0,
			SYS_kobject_send, &res);

	ret = (long)res.a0;
	*actual_data = (size_t)res.a1;
	*actual_extra = (size_t)res.a2;

	return ret;
}


long kobject_write(int handle, void *data, size_t data_size,
		void *extra, size_t extra_size, uint32_t timeout)
{
	return syscall(SYS_kobject_send, handle, data, data_size,
			extra, extra_size, timeout);

}

int kobject_reply(int handle, long token, long err_code, int fd, int right)
{
	if ((err_code == 0) && (fd <= 0))
		return -EINVAL;

	return syscall(SYS_kobject_reply, token, err_code, fd, right);
}

int kobject_reply_simple(int handle, long err_code)
{
	return kobject_reply(handle, 0, err_code, -1, 0);
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
