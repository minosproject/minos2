#ifndef __LIBC_KOBJECT_H__
#define __LIBC_KOBJECT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdint.h>
#include <minos/kobject_uapi.h>

/*
 * kobject related API.
 */
int kobject_open(int handle);

int kobject_connect(char *path, int right);

int kobject_close(int handle);

int kobject_create(char *name, int type, int right, int right_req,
		unsigned long data);

long kobject_read(int handle, void *data, size_t data_size,
		size_t *actual_data, void *extra, size_t extra_size,
		size_t *actual_extra, uint32_t timeout);

long kobject_write(int handle, void *data, size_t data_size,
		void *extra, size_t extra_size, uint32_t timeout);

int kobject_reply(int handle, long token, long err_code, int fd, int right);

void *kobject_mmap(int handle);

int kobject_unmap(int handle);

long kobject_ctl(int handle, int action, unsigned long data);

int grant(int proc, int handle, int right, int release);

#ifdef __cplusplus
}
#endif

#endif
