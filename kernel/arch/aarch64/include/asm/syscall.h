#ifndef __ASM_SYSCALL_H__
#define __ASM_SYSCALL_H__

#define __NR_kobject_create 0
#define __NR_kobject_open 1
#define __NR_kobject_close 2
#define __NR_kobject_recv 3
#define __NR_kobject_send 4
#define __NR_kobject_reply 5
#define __NR_kobject_reply_recv 6
#define __NR_kobject_ctl 7
#define __NR_kobject_mmap 8
#define __NR_kobject_munmap 9

#define __NR_grant 10

#define __NR_futex 11
#define __NR_yield 12

#define __NR_map 13
#define __NR_unmap 14
#define __NR_trans 15

#undef __NR_syscalls
#define __NR_syscalls 16

struct syscall_regs {
	unsigned long regs[8];
};

#endif
