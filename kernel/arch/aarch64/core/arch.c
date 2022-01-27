/*
 * Copyright (C) 2018 Min Le (lemin9538@gmail.com)
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

#include <asm/aarch64_common.h>
#include <asm/aarch64_helper.h>
#include <asm/arch.h>
#include <minos/string.h>
#include <minos/print.h>
#include <minos/sched.h>
#include <minos/calltrace.h>
#include <minos/smp.h>
#include <minos/of.h>
#include <minos/platform.h>
#include <minos/task.h>
#include <minos/console.h>
#include <minos/ramdisk.h>
#include <asm/tcb.h>
#include <minos/vspace.h>
#include <minos/proc.h>
#include <minos/mm.h>

#ifdef CONFIG_VIRT
#define read_esr()	read_esr_el2()
#else
#define read_esr()	read_esr_el1()
#endif

void arch_dump_register(gp_regs *regs)
{
	unsigned long spsr;

	if (!regs)
		return;

	spsr = regs->pstate;
	pr_fatal("SPSR:0x%x Mode:%d-%s F:%d I:%d A:%d D:%d NZCV:%x\n",
			spsr, (spsr & 0x7), (spsr & 0x8) ?
			"aarch64" : "aarch32", (spsr & (BIT(6))) >> 6,
			(spsr & (BIT(7))) >> 7, (spsr & (BIT(8))) >> 8,
			(spsr & (BIT(9))) >> 9, spsr >> 28);

	pr_fatal("x0:0x%p x1:0x%p x2:0x%p\n",
			regs->x0, regs->x1, regs->x2);
	pr_fatal("x3:0x%p x4:0x%p x5:0x%p\n",
			regs->x3, regs->x4, regs->x5);
	pr_fatal("x6:0x%p x7:0x%p x8:0x%p\n",
			regs->x6, regs->x7, regs->x8);
	pr_fatal("x9:0x%p x10:0x%p x11:0x%p\n",
			regs->x9, regs->x10, regs->x11);
	pr_fatal("x12:0x%p x13:0x%p x14:0x%p\n",
			regs->x12, regs->x13, regs->x14);
	pr_fatal("x15:0x%p x16:0x%p x17:0x%p\n",
			regs->x15, regs->x16, regs->x17);
	pr_fatal("x18:0x%p x19:0x%p x20:0x%p\n",
			regs->x18, regs->x19, regs->x20);
	pr_fatal("x21:0x%p x22:0x%p x23:0x%p\n",
			regs->x21, regs->x22, regs->x23);
	pr_fatal("x24:0x%p x25:0x%p x26:0x%p\n",
			regs->x24, regs->x25, regs->x26);
	pr_fatal("x27:0x%p x28:0x%p x29:0x%p\n",
			regs->x27, regs->x28, regs->x29);
	pr_fatal("lr:0x%p sp_el0:0x%p spsr:0x%p\n",
			regs->lr, regs->sp, regs->pstate);
	pr_fatal("pc:0x%p esr:0x%p\n", regs->pc, read_esr());
}

void arch_dump_stack(gp_regs *regs, unsigned long *stack)
{
	struct task *task = get_current_task();
	unsigned long fp, lr = 0;

	if ((task) && os_is_running()) {
		pr_fatal("current task: tid:%d prio:%d name:%s\n",
				get_task_tid(task), get_task_prio(task),
				task->name);
	}

	arch_dump_register(regs);

	if (!stack) {
		if (regs) {
			fp = regs->x29;
			lr = regs->pc;
		} else {
			fp = arch_get_fp();
			lr = arch_get_lr();
		}
	} else {
		fp = *stack;
	}

	pr_fatal("Call Trace :\n");
	pr_fatal("------------ cut here ------------\n");
	do {
		print_symbol(lr);

		if ((fp < (unsigned long)task->stack_bottom) ||
				(fp >= (unsigned long)task->stack_top))
				break;

		lr = *(unsigned long *)(fp + sizeof(unsigned long));
		lr -= 4;
		fp = *(unsigned long *)fp;
	} while (1);
}

int arch_taken_from_guest(gp_regs *regs)
{
	/* TBD */
	return ((regs->pstate & 0xf) != (AARCH64_SPSR_EL2h));
}

static inline uint64_t task_ttbr_value(struct task *task)
{
	struct vspace *vs = &task->proc->vspace;

	return (uint64_t)vtop(vs->pgdp) | ((uint64_t)vs->asid << 48);
}

#if defined(CONFIG_VIRT) && !defined(CONFIG_ARM_VHE)
static void save_cpu_context_no_vhe(struct task *task, struct cpu_context *c)
{
	c->hcr_el2 = read_sysreg(HCR_EL2);

	c->sctlr_el1 = read_sysreg(SCTLR_EL1);
	c->cpacr_el1 = read_sysreg(CPACR_EL1);
	c->mdscr_el1 = read_sysreg(MDSCR_EL1);
	c->cntvoff_el2 = read_sysreg(CNTVOFF_EL2);
	c->cntkctl_el1 = read_sysreg(CNTKCTL_EL1);
	c->cntv_ctl_el0 = read_sysreg(CNTV_CTL_EL0);
}

static void restore_cpu_context_no_vhe(struct task *task, struct cpu_context *c)
{
	write_sysreg(c->hcr_el2, HCR_EL2);

	write_sysreg(c->sctlr_el1, SCTLR_EL1);
	write_sysreg(c->cpacr_el1, CPACR_EL1);
	write_sysreg(c->mdscr_el1, MDSCR_EL1);
	write_sysreg(c->cntvoff_el2, CNTVOFF_EL2);
	write_sysreg(c->cntkctl_el1, CNTKCTL_EL1);
	write_sysreg(c->cntv_ctl_el0, CNTV_CTL_EL0);
}
#else
static void restore_cpu_context_vhe(struct task *task, struct cpu_context *c)
{

}

static void save_cpu_context_vhe(struct task *task, struct cpu_context *c)
{

}
#endif

static void user_task_sched_out(struct task *task)
{
	struct cpu_context *c = &task->cpu_context;
	extern void fpsimd_state_save(struct task *task,
		struct fpsimd_context *c);

#if defined( CONFIG_VIRT) && !defined(CONFIG_ARM_VHE)
	save_cpu_context_no_vhe(task, c);
#else
	save_cpu_context_vhe(task, c);
#endif
	c->tpidr_el0 = read_sysreg(TPIDR_EL0);
	fpsimd_state_save(task, &c->fpsimd_state);
}

static void user_task_sched_in(struct task *task)
{
	struct cpu_context *c = &task->cpu_context;
	extern void fpsimd_state_restore(struct task *task,
		struct fpsimd_context *c);

#if defined(CONFIG_VIRT) && !defined(CONFIG_ARM_VHE)
	restore_cpu_context_no_vhe(task, c);
#else
	restore_cpu_context_vhe(task, c);
#endif

	write_sysreg(c->tpidr_el0, TPIDR_EL0);
	write_sysreg(c->tpidrro_el0, TPIDRRO_EL0);
	fpsimd_state_restore(task, &c->fpsimd_state);

	/*
	 * switch to the process's page table
	 */
#if defined(CONFIG_VIRT) && !defined(CONFIG_ARM_VHE)
	write_sysreg(c->ttbr_el0, VTTBR_EL2);
#else
	write_sysreg(c->ttbr_el0, TTBR0_EL1);
#endif
}

void kernel_task_sched_out(struct task *task)
{

}

void kernel_task_sched_in(struct task *task)
{

}

static void aarch64_init_user_task(struct task *task, gp_regs *regs)
{
	regs->pstate = AARCH64_SPSR_EL0t;

	task->sched_out = user_task_sched_out;
	task->sched_in = user_task_sched_in;

	task->cpu_context.tpidr_el0 = 0;
	task->cpu_context.tpidrro_el0 = (uint64_t)task->proc->pid << 32 | (task->tid);
	task->cpu_context.ttbr_el0 = task_ttbr_value(task);
}

static void aarch64_init_kernel_task(struct task *task, gp_regs *regs)
{
	extern void aarch64_task_exit(void);

	/*
	 * if the task is not a deadloop the task will exist
	 * by itself like below
	 *	int main(int argc, char **argv)
	 *	{
	 *		do_some_thing();
	 *		return 0;
	 *	}
	 * then the lr register should store a function to
	 * handle the task's exist
	 *
	 * kernel task will not use fpsimd now, so kernel task
	 * do not need to save/restore it
	 */
	regs->lr = (uint64_t)aarch64_task_exit;

#ifdef CONFIG_VIRT
	regs->pstate = AARCH64_SPSR_EL2h;
#else
	regs->pstate = AARCH64_SPSR_EL1h;
#endif

	task->sched_out = kernel_task_sched_out;
	task->sched_in = kernel_task_sched_in;
}

void arch_init_task(struct task *task, void *entry, void *user_sp, void *arg)
{
	gp_regs *regs = stack_to_gp_regs(task->stack_top);

	memset(regs, 0, sizeof(gp_regs));
	task->stack_base = (void *)regs;

	regs->pc = (uint64_t)entry;
	regs->sp = (uint64_t)user_sp;

	if (task->flags & TASK_FLAGS_KERNEL)
		aarch64_init_kernel_task(task, regs);
	else
		aarch64_init_user_task(task, regs);
}

void arch_set_task_user_stack(struct task *task, unsigned long stack)
{
	gp_regs *regs = stack_to_gp_regs(task->stack_top);
	regs->sp = stack;
}

void arch_set_task_reg0(struct task *task, unsigned long data)
{
	gp_regs *regs = stack_to_gp_regs(task->stack_top);
	regs->x0 = data;
}

void arch_set_tls(struct task *task, unsigned long tls)
{
	struct cpu_context *ctx = &task->cpu_context;

	ctx->tpidr_el0 = tls;
}

void arch_set_task_entry_point(struct task *task, long entry)
{
	gp_regs *regs = stack_to_gp_regs(task->stack_top);
	regs->pc = entry;
}

void arch_release_task(struct task *task)
{

}

static int __init_text aarch64_init_percpu(void)
{
	uint64_t reg;

	reg = read_CurrentEl();
	pr_notice("current EL is %d\n", GET_EL(reg));

	/*
	 * set IMO and FMO let physic irq and fiq taken to
	 * EL2, without this irq and fiq will not send to
	 * the cpu
	 */
#ifdef CONFIG_VIRT
	reg = read_sysreg64(HCR_EL2);
	reg |= HCR_EL2_IMO | HCR_EL2_FMO | HCR_EL2_AMO;
	write_sysreg64(reg, HCR_EL2);
	write_sysreg64(0x3 << 20, CPACR_EL2);
	dsb();
#else
	write_sysreg64(0x3 << 20, CPACR_EL1);
	isb();
#endif

	return 0;
}
arch_initcall_percpu(aarch64_init_percpu);

int arch_early_init(void)
{
#ifdef CONFIG_DEVICE_TREE
	/*
	 * set up the platform from the dtb file then get the spin
	 * table information if the platform is using spin table to
	 * wake up other cores
	 */
	of_setup_platform();
#endif
	return 0;
}

int __arch_init(void)
{
#ifdef CONFIG_DEVICE_TREE
	of_parse_device_tree();
#endif
	return 0;
}

uint64_t cpuid_to_affinity(int cpuid)
{
	int aff0, aff1;

	if (cpu_has_feature(ARM_FEATURE_MPIDR_SHIFT))  {
		if (cpuid < CONFIG_NR_CPUS_CLUSTER0)
			return (cpuid << MPIDR_EL1_AFF1_LSB);
		else {
			aff0 = cpuid - CONFIG_NR_CPUS_CLUSTER0;
			aff1 = 1;

			return (aff1 << MPIDR_EL1_AFF2_LSB) |
				(aff0 << MPIDR_EL1_AFF1_LSB);
		}
	} else {
		if (cpuid < CONFIG_NR_CPUS_CLUSTER0) {
			return cpuid;
		} else {
			aff0 = cpuid - CONFIG_NR_CPUS_CLUSTER0;
			aff1 = 1;

			return (aff1 << MPIDR_EL1_AFF1_LSB) + aff0;
		}
	}
}

int affinity_to_cpuid(unsigned long affinity)
{
	int aff0, aff1;

	if (cpu_has_feature(ARM_FEATURE_MPIDR_SHIFT))  {
		aff0 = (affinity >> MPIDR_EL1_AFF1_LSB) & 0xff;
		aff1 = (affinity >> MPIDR_EL1_AFF2_LSB) & 0xff;
	} else {
		aff0 = (affinity >> MPIDR_EL1_AFF0_LSB) & 0xff;
		aff1 = (affinity >> MPIDR_EL1_AFF1_LSB) & 0xff;
	}

	return (aff1 * CONFIG_NR_CPUS_CLUSTER0) + aff0;
}

void arch_smp_init(phy_addr_t *smp_h_addr)
{
#ifdef CONFIG_DEVICE_TREE
	of_spin_table_init(smp_h_addr);
#endif
}

static pgd_t *__arch_alloc_process_page_table(void)
{
	pgd_t *pgt;
	/*
	 * 3 levels page table 4kb page size and 8K PGD with 1TB
	 * virtual address.
	 */
	pgt = get_free_pages(1, GFP_KERNEL);
	if (!pgt)
		return NULL;

	memset(pgt, 0, PAGE_SIZE);
	return pgt;
}

pgd_t *arch_alloc_process_page_table(void)
{
	/*
	 * for VHE system, allocate process page table with ASID
	 * otherwise allocate virtual machine page table with
	 * VMID. all use 1TB virtual address space
	 */
#if defined(CONFIG_VIRT) && !defined(CONFIG_ARM_VHE)
	return arch_alloc_guest_pgd();
#else
	return __arch_alloc_process_page_table();
#endif
}

void arch_set_task_reg(struct task *task, int index, unsigned long value)
{
	unsigned long *regs = (unsigned long *)task->stack_base;

	ASSERT(index < (sizeof(gp_regs) / sizeof(unsigned long)));
	regs[index] = value;
}

int arch_get_asid_size(void)
{
	// TBD, get from the register
	return 256;
}

void arch_main(void *dtb)
{
	char *name = NULL;
	extern void boot_main(void);

	pr_notice("Starting Minos AARCH64\n");
	pr_notice("DTB address [0x%x]\n", dtb);

	/*
	 * the dtb file need to store at the end of the os memory
	 * region and the size can not beyond 2M, also it must
	 * 4K align, memory management will not protect this area
	 * so please put the dtb data to a right place
	 */
#ifdef CONFIG_DTB_LOAD_ADDRESS
	of_init((void *)ptov(CONFIG_DTB_LOAD_ADDRESS));
#else
	of_init((void *)ptov(dtb));
#endif

	of_get_console_name(&name);
	console_init(name);

	/*
	 * here start the kernel
	 */
	boot_main();
}
