#ifndef __MINOS_SYSCALL_H__
#define __MINOS_SYSCALL_H__

#include <minos/types.h>
#include <asm/syscall.h>

extern void sys_sched_yield(void);

extern int sys_kobject_connect(char __user *path, right_t right);
extern int sys_kobject_close(int handle);
extern int sys_kobject_open(handle_t handle);

extern handle_t sys_kobject_create(int type, int right,
		right_t right_req, unsigned long data);

extern ssize_t sys_kobject_recv(handle_t handle, void __user *data, size_t data_size,
		size_t *actual_data, void __user *extra, size_t extra_size,
		size_t *actual_extra, uint32_t timeout);

extern ssize_t sys_kobject_send(handle_t handle, void __user *data, size_t data_size,
		void __user *extra, size_t extra_size, uint32_t timeout);

extern int sys_kobject_reply(handle_t handle, long token,
		long err_code, handle_t fd, right_t fd_right);

extern long sys_futex(uint32_t __user *uaddr, int op, uint32_t val,
		struct timespec __user *utime,
		uint32_t __user *uaddr2, uint32_t val3);

extern int sys_unmap(handle_t proc_handle, handle_t pma_handle);

extern int sys_map(handle_t proc_handle, handle_t pma_handle,
		unsigned long virt, size_t size, right_t right);

extern handle_t sys_grant(handle_t proc, handle_t handle,
		right_t right, int release);

extern int sys_kobject_munmap(handle_t handle);

extern void *sys_kobject_mmap(handle_t handle);

extern long sys_kobject_ctl(handle_t handle, int req, unsigned long data);

#endif
