#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"
#include "aarch64_svc.h"

int kobject_close(int handle)
{
	return syscall(SYS_kobject_close, handle);
}

int kobject_create(int type, unsigned long data)
{
	return syscall(SYS_kobject_create, type, data);
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
			SYS_kobject_recv, &res);

	ret = (long)res.a0;

	if (actual_data)
		*actual_data = (size_t)res.a1;
	if (actual_extra)
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
	return syscall(SYS_kobject_reply, handle, token, err_code, fd, right);
}

int kobject_reply_errcode(int handle, long token, long err_code)
{
	return kobject_reply(handle, token, err_code, -1, 0);
}

int kobject_mmap(int handle, void **addr, size_t *msize)
{
	struct aarch64_svc_res res;
	int ret;

	aarch64_svc_call((unsigned long)handle, 0, 0, 0, 0,
			0, 0, SYS_kobject_mmap, &res);
	ret = (long)res.a0;
	if (addr)
		*addr = (void *)res.a1;
	if (msize)
		*msize = (size_t)res.a2;

	return ret;
}

int kobject_munmap(int handle)
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
