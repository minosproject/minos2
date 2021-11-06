#ifndef __LIBC_KOBJECT_H__
#define __LIBC_KOBJECT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdint.h>
#include <minos/kobject_uapi.h>

#define KR_R KOBJ_RIGHT_READ
#define KR_W KOBJ_RIGHT_WRITE
#define KR_X KOBJ_RIGHT_EXEC
#define KR_C KOBJ_RIGHT_CTL
#define KR_M KOBJ_RIGHT_MMAP

#define KR_RW (KR_R | KR_W)
#define KR_RWX (KR_R | KR_W | KR_X)
#define KR_RWC (KR_R | KR_W | KR_C)
#define KR_RWM (KR_R | KR_W | KR_M)
#define KR_RWCM (KR_R | KR_W | KR_C | KR_M)
#define KR_RM (KR_R | KR_M)
#define KR_WM (KR_W | KR_M)
#define KR_RC (KR_R | KR_C)
#define KR_WC (KR_W | KR_C)
#define KR_RCM	(KR_R | KR_C | KR_M)
#define KR_WCM	(KR_W | KR_C | KR_M)

/*
 * kobject related API.
 */
int kobject_open(int handle);

int kobject_close(int handle);

int kobject_create(int type, unsigned long data);

long kobject_read(int handle, void *data, size_t data_size,
		size_t *actual_data, void *extra, size_t extra_size,
		size_t *actual_extra, uint32_t timeout);

static inline long kobject_read_simple(int handle, void *data,
		size_t data_size, uint32_t timeout)
{
	return kobject_read(handle, data, data_size, (size_t *)0,
			(void *)0, 0, (size_t *)0, timeout);
}

long kobject_write(int handle, void *data, size_t data_size,
		void *extra, size_t extra_size, uint32_t timeout);

int kobject_reply(int handle, long token, long err_code, int fd, int right);

int kobject_reply_errcode(int handle, long token, long err_code);

int kobject_mmap(int handle, void *addr, size_t *msize);

int kobject_munmap(int handle);

long kobject_ctl(int handle, int action, unsigned long data);

int grant(int proc, int handle, int right);

int kobject_create_endpoint(size_t shmem_size);

int kobject_create_port(void);

int kobject_create_notify(void);

int kobject_create_pma(size_t memsize, int right);

int kobject_create_consequent_pma(size_t memsize, int right);

static inline int kobject_reply_handle(int fd, long token,
		int handle, int right)
{
	if (handle > 0)
		return kobject_reply(fd, token, 0, handle, right);
	else
		return kobject_reply(fd, token, handle, 0, 0);
}

#ifdef __cplusplus
}
#endif

#endif
