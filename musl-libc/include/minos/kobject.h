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
#define KR_G KOBJ_RIGHT_GRANT
#define KR_S KOBJ_RIGHT_SHARED

#define KR_RW (KR_R | KR_W)
#define KR_RWX (KR_R | KR_W | KR_X)
#define KR_RWG (KR_R | KR_W | KR_G)
#define KR_RWC (KR_R | KR_W | KR_C)
#define KR_RWCG (KR_R | KR_W | KR_G | KR_C)
#define KR_RWCMG (KR_R | KR_W | KR_G | KR_C | KR_M)
#define KR_RMG (KR_R | KR_M | KR_G)
#define KR_WMG (KR_W | KR_M | KR_G)
#define KR_WCMG (KR_W | KR_C | KR_M | KR_G)
#define KR_RCMG (KR_R | KR_C | KR_M | KR_G)
#define KR_RM (KR_R | KR_M)
#define KR_WM (KR_W | KR_M)
#define KR_RC (KR_R | KR_C)
#define KR_WC (KR_W | KR_C)
#define KR_WCG (KR_W | KR_C | KR_G)
#define KR_RCG (KR_R | KR_C | KR_G)
#define KR_WG (KR_W | KR_G)
#define KR_GG (KR_R | KR_G)

/*
 * kobject related API.
 */
int kobject_open(int handle);

int kobject_close(int handle);

int kobject_create(int type, int right,
		int right_req, unsigned long data);

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

void *kobject_mmap(int handle);

int kobject_munmap(int handle);

long kobject_ctl(int handle, int action, unsigned long data);

int grant(int proc, int handle, int right);

int sys_connect_service(const char *path, int right);

int kobject_create_endpoint(int right, int right_req, size_t shmem_size);

int kobject_create_port(int right, int right_req);

int kobject_create_notify(int right, int right_req);

static inline int kobject_reply_handle(int fd, long token,
		int handle, int right)
{
	if (handle >= 0)
		return kobject_reply(fd, token, 0, handle, right);
	else
		return kobject_reply(fd, token, handle, 0, 0);
}

#ifdef __cplusplus
}
#endif

#endif
