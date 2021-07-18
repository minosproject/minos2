#ifndef __ASM_SYSCALL_H__
#define __ASM_SYSCALL_H__

#define __NR_poll_wait 0

#define __NR_kobject_open 2
#define __NR_kobject_create 3
#define __NR_kobject_destroy 4
#define __NR_kobject_recv 5
#define __NR_kobject_send 6
#define __NR_kobject_reply 7
#define __NR_kobject_connect 8
#define __NR_kobject_close 9
#define __NR_kobject_ctl 10
#define __NR_kobject_mmap 11
#define __NR_kobject_munmap 12
#define __NR_kobject_listen 13

#define __NR_grant 14

#define __NR_futex 15
#define __NR_yield 16

#define __NR_map 17
#define __NR_unmap 18

#undef __NR_syscalls
#define __NR_syscalls 19

struct syscall_regs {
	unsigned long regs[8];
};

#endif
