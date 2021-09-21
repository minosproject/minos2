/*
 * Copyright (C) 2020 Min Le (lemin9538@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <minos/minos.h>
#include <minos/syscall.h>
#include <minos/kobject.h>
#include <minos/console.h>
#include <minos/time.h>
#include <minos/poll.h>

struct aarch64_syscall_reg {
	unsigned long regs[8];
} __packed;

typedef void (*syscall_handler_t)(gp_regs *regs);

static void aarch64_syscall_unsupport(gp_regs *regs)
{
	pr_err("Unsupported syscall:%d\n", regs->x8);
	regs->x0 = -ENOENT;
}

static void __sys_kobject_close(gp_regs *regs)
{
	regs->x0 = sys_kobject_close((handle_t)regs->x0);
}

static void __sys_kobject_create(gp_regs *regs)
{
	regs->x0 = sys_kobject_create(
			(int)regs->x0,
			(int)regs->x1,
			(unsigned long)regs->x2,
			(unsigned long)regs->x3);
}

static void __sys_kobject_recv(gp_regs *regs)
{
	size_t data = 0, extra = 0;

	regs->x0 = sys_kobject_recv(
			(int)regs->x0,
			(void __user *)regs->x1,
			(size_t)regs->x2,
			&data,
			(void __user *)regs->x3,
			(size_t)regs->x4,
			&extra,
			(uint32_t)regs->x5);
	regs->x1 = data;
	regs->x2 = extra;
}

static void __sys_kobject_send(gp_regs *regs)
{
	regs->x0 = sys_kobject_send(
			(int)regs->x0,
			(void __user *)regs->x1,
			(size_t)regs->x2,
			(void __user *)regs->x3,
			(size_t)regs->x4,
			(uint32_t)regs->x5);
}

static void __sys_kobject_reply(gp_regs *regs)
{
	regs->x0 = sys_kobject_reply(
			(int)regs->x0,
			(unsigned long)regs->x1,
			(long)regs->x2,
			(handle_t)regs->x3,
			(right_t)regs->x4);
}

static void __sys_kobject_ctl(gp_regs *regs)
{
	regs->x0 = sys_kobject_ctl((handle_t)regs->x0,
			(int)regs->x1,
			(unsigned long)regs->x2);
}

static void __sys_kobject_mmap(gp_regs *regs)
{
	regs->x0 = (unsigned long)sys_kobject_mmap((handle_t)regs->x0);
}

static void __sys_kobject_munmap(gp_regs *regs)
{
	regs->x0 = sys_kobject_munmap((handle_t)regs->x0);
}

static void __sys_kobject_open(gp_regs *regs)
{
	regs->x0 = sys_kobject_open((handle_t)regs->x0);
}

static void __sys_map(gp_regs *regs)
{
	regs->x0 = sys_map((handle_t)regs->x0,
			(handle_t)regs->x1,
			(unsigned long)regs->x2,
			(size_t)regs->x3,
			(right_t)regs->x4);
}

static void __sys_unmap(gp_regs *regs)
{
	regs->x0 = sys_unmap((handle_t)regs->x0,
			(handle_t)regs->x1);
}

static void __sys_yield(gp_regs *regs)
{
	sys_sched_yield();
}

static void __sys_futex(gp_regs *regs)
{
	regs->x0 = sys_futex(
			(uint32_t __user *)regs->x0,
			(int)regs->x1,
			(uint32_t)regs->x2,
			(struct timespec __user *)regs->x3,
			(uint32_t __user *)regs->x4,
			(uint32_t)regs->x5);
}

static void __sys_grant(gp_regs *regs)
{
	regs->x0 = sys_grant((handle_t)regs->x0,
			(handle_t)regs->x1,
			(right_t)regs->x2,
			(int)regs->x3);
}

static syscall_handler_t __syscall_table[] = {
	[0 ... __NR_syscalls] 		= aarch64_syscall_unsupport,

	[__NR_kobject_open]		= __sys_kobject_open,
	[__NR_kobject_create]		= __sys_kobject_create,
	[__NR_kobject_reply]		= __sys_kobject_reply,
	[__NR_kobject_send]		= __sys_kobject_send,
	[__NR_kobject_recv]		= __sys_kobject_recv,
	[__NR_kobject_close]		= __sys_kobject_close,
	[__NR_kobject_ctl]		= __sys_kobject_ctl,
	[__NR_kobject_mmap]		= __sys_kobject_mmap,
	[__NR_kobject_munmap]		= __sys_kobject_munmap,

	[__NR_grant]			= __sys_grant,

	[__NR_yield]			= __sys_yield,
	[__NR_futex]			= __sys_futex,

	[__NR_map]			= __sys_map,
	[__NR_unmap]			= __sys_unmap,
};

void aarch64_do_syscall(gp_regs *regs)
{
	int nr = regs->x8;

	arch_enable_local_irq();

	current->user_gp_regs = regs;
	if (nr >= __NR_syscalls) {
		regs->x0 = -EINVAL;
		return;
	}
	__syscall_table[nr](regs);

	arch_disable_local_irq();
}
