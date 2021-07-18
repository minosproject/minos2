/*
 * Copyright (C) 2019 Min Le (lemin9538@gmail.com)
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
#include <virt/vm.h>
#include <virt/vmodule.h>
#include <asm/arch.h>
#include <minos/string.h>
#include <minos/print.h>
#include <minos/sched.h>
#include <minos/calltrace.h>
#include <minos/smp.h>
#include <minos/of.h>
#include <minos/platform.h>
#include <minos/task.h>
#include <virt/vm.h>
#include <virt/virq.h>
#include <virt/os.h>

/*
 * 0 is reserved as an invalid value.
 * Order should be kept in sync with the save/restore code.
 */
enum vcpu_sysreg {
	__INVALID_SYSREG__,
	MPIDR_EL1,	/* MultiProcessor Affinity Register */
	CSSELR_EL1,	/* Cache Size Selection Register */
	SCTLR_EL1,	/* System Control Register */
	ACTLR_EL1,	/* Auxiliary Control Register */
	CPACR_EL1,	/* Coprocessor Access Control */
	TTBR0_EL1,	/* Translation Table Base Register 0 */
	TTBR1_EL1,	/* Translation Table Base Register 1 */
	TCR_EL1,	/* Translation Control Register */
	ESR_EL1,	/* Exception Syndrome Register */
	AFSR0_EL1,	/* Auxiliary Fault Status Register 0 */
	AFSR1_EL1,	/* Auxiliary Fault Status Register 1 */
	FAR_EL1,	/* Fault Address Register */
	MAIR_EL1,	/* Memory Attribute Indirection Register */
	VBAR_EL1,	/* Vector Base Address Register */
	CONTEXTIDR_EL1,	/* Context ID Register */
	TPIDR_EL0,	/* Thread ID, User R/W */
	TPIDRRO_EL0,	/* Thread ID, User R/O */
	TPIDR_EL1,	/* Thread ID, Privileged */
	AMAIR_EL1,	/* Aux Memory Attribute Indirection Register */
	CNTKCTL_EL1,	/* Timer Control Register (EL1) */
	PAR_EL1,	/* Physical Address Register */
	MDSCR_EL1,	/* Monitor Debug System Control Register */
	MDCCINT_EL1,	/* Monitor Debug Comms Channel Interrupt Enable Reg */
	DISR_EL1,	/* Deferred Interrupt Status Register */

	/* Performance Monitors Registers */
	PMCR_EL0,	/* Control Register */
	PMSELR_EL0,	/* Event Counter Selection Register */
	PMEVCNTR0_EL0,	/* Event Counter Register (0-30) */
	PMEVCNTR30_EL0 = PMEVCNTR0_EL0 + 30,
	PMCCNTR_EL0,	/* Cycle Counter Register */
	PMEVTYPER0_EL0,	/* Event Type Register (0-30) */
	PMEVTYPER30_EL0 = PMEVTYPER0_EL0 + 30,
	PMCCFILTR_EL0,	/* Cycle Count Filter Register */
	PMCNTENSET_EL0,	/* Count Enable Set Register */
	PMINTENSET_EL1,	/* Interrupt Enable Set Register */
	PMOVSSET_EL0,	/* Overflow Flag Status Set Register */
	PMSWINC_EL0,	/* Software Increment Register */
	PMUSERENR_EL0,	/* User Enable Register */

	/* 32bit specific registers. Keep them at the end of the range */
	DACR32_EL2,	/* Domain Access Control Register */
	IFSR32_EL2,	/* Instruction Fault Status Register */
	FPEXC32_EL2,	/* Floating-Point Exception Control Register */
	DBGVCR32_EL2,	/* Debug Vector Catch Register */

	NR_SYS_REGS	/* Nothing after this line! */
};

struct aarch64_system_context {
	uint64_t vbar_el1;
	uint64_t esr_el1;
	uint64_t sp_el1;
	uint64_t sp_el0;
	uint64_t elr_el1;
	uint64_t vmpidr;
	uint64_t vpidr;
	uint64_t sctlr_el1;
	uint64_t hcr_el2;
	uint64_t spsr_el1;
	uint64_t far_el1;
	uint64_t actlr_el1;
	uint64_t tpidr_el1;
	uint64_t csselr;
	uint64_t cpacr;
	uint64_t contextidr;
	uint64_t tpidr_el0;
	uint64_t tpidrro_el0;
	uint64_t cntkctl;
	uint64_t afsr0;
	uint64_t afsr1;
	uint32_t teecr;
	uint32_t teehbr;
	uint32_t dacr32_el2;
	uint32_t ifsr32_el2;
}__align(sizeof(unsigned long));

#define AARCH64_SYSTEM_VMODULE	"aarch64-system"

static uint32_t mpidr_el1[NR_CPUS];

void arch_set_virq_flag(void)
{
	uint64_t hcr_el2;

	hcr_el2 = read_sysreg(HCR_EL2);
	hcr_el2 |= HCR_EL2_VI;
	write_sysreg(hcr_el2, HCR_EL2);
	dsb();
}

void arch_set_vfiq_flag(void)
{
	uint64_t hcr_el2;

	hcr_el2 = read_sysreg(HCR_EL2);
	hcr_el2 |= HCR_EL2_VF;
	write_sysreg(hcr_el2, HCR_EL2);
	dsb();
}

void arch_clear_virq_flag(void)
{
	uint64_t hcr_el2;

	hcr_el2 = read_sysreg(HCR_EL2);
	hcr_el2 &= ~HCR_EL2_VI;
	hcr_el2 &= ~HCR_EL2_VF;
	write_sysreg(hcr_el2, HCR_EL2);
	dsb();
}

void arch_clear_vfiq_flag(void)
{
	uint64_t hcr_el2;

	hcr_el2 = read_sysreg(HCR_EL2);
	hcr_el2 &= ~HCR_EL2_VF;
	write_sysreg(hcr_el2, HCR_EL2);
	dsb();
}

void arch_init_vcpu(struct vcpu *vcpu, void *entry, void *arg)
{
	struct task *task = vcpu->task;
	gp_regs *regs;

	regs = stack_to_gp_regs(task->stack_origin);
	memset(regs, 0, sizeof(gp_regs));
	task->stack_base = task->stack_origin - sizeof(gp_regs);

	regs->pc = (uint64_t)entry;

	if (task_is_64bit(vcpu->task))
		regs->pstate = AARCH64_SPSR_EL1h | \
				AARCH64_SPSR_F | \
				AARCH64_SPSR_I | \
				AARCH64_SPSR_A;
	else
		regs->pstate = AARCH32_SVC | \
				AARCH64_SPSR_F | \
				AARCH64_SPSR_I | \
				AARCH64_SPSR_A | (1 << 4);
}

static void aarch64_system_state_init(struct vcpu *vcpu, void *c)
{
	uint64_t value;
	struct aarch64_system_context *context =
			(struct aarch64_system_context *)c;

	memset(context, 0, sizeof(*context));

	/*
	 * HVC : enable hyper call function
	 * TWI : trap wfi - default enable, disable by dts
	 * TWE : trap wfe - default disable
	 * TIDCP : Trap implementation defined functionality
	 * IMP : physical irq routing
	 * FMO : physical firq routing
	 * BSU_IS : Barrier Shareability upgrade
	 * FB : force broadcast when do some tlb ins
	 * PTW : protect table walk
	 * TSC : trap smc ins
	 * TACR : Trap Auxiliary Control Registers
	 * AMO : Physical SError interrupt routing.
	 * RW : low level is 64bit, when 0 is 32 bit
	 * VM : enable virtualzation
	 */
	value = read_sysreg64(HCR_EL2);
	context->hcr_el2 = value | HCR_EL2_VM |
		     HCR_EL2_TIDCP | HCR_EL2_IMO | HCR_EL2_FMO |
		     HCR_EL2_BSU_IS | HCR_EL2_FB | HCR_EL2_PTW |
		     HCR_EL2_TSC | HCR_EL2_TACR | HCR_EL2_AMO;

	/*
	 * usually there will be so many wfis from the VM
	 * in some case this will have much infulence to
	 * the system, add this flag to disable WFI trap.
	 */
	if (!(vcpu->vm->flags & VM_FLAGS_NATIVE_WFI))
		context->hcr_el2 |= HCR_EL2_TWI;

	if (task_is_64bit(vcpu->task))
		context->hcr_el2 |= HCR_EL2_RW;

	/*
	 * this require HVM's vcpu affinity need start with 0
	 */
	if (vm_is_hvm(vcpu->vm))
		context->vmpidr = cpuid_to_affinity(get_vcpu_id(vcpu));
	else
		context->vmpidr = get_vcpu_id(vcpu);

	pr_notice("vmpidr is 0x%x\n", context->vmpidr);

	context->cpacr = 0x3 << 20;

	if (vm_is_native(vcpu->vm))
		context->vpidr = mpidr_el1[vcpu_affinity(vcpu)];
	else
		context->vpidr = 0x410fc050;	/* arm fvp */

	/*
	 * enable dc zva trap, the apple soc use zva size 64
	 * fixed, which may not equal to the target platform
	 * so need trap dc zva
	 */
	if (vcpu->vm->os->type == OS_TYPE_XNU)
		context->hcr_el2 |= HCR_EL2_TDZ;
}

static void aarch64_system_state_resume(struct vcpu *vcpu, void *c)
{
	aarch64_system_state_init(vcpu, c);
}

static void aarch64_system_state_save(struct vcpu *vcpu, void *c)
{
	struct aarch64_system_context *context =
			(struct aarch64_system_context *)c;

	context->vbar_el1 = read_sysreg(ARM64_VBAR_EL1);
	context->esr_el1 = read_sysreg(ARM64_ESR_EL1);
	context->elr_el1 = read_sysreg(ARM64_ELR_EL1);
	context->vmpidr = read_sysreg(ARM64_VMPIDR_EL2);
	context->vpidr = read_sysreg(ARM64_VPIDR_EL2);
	context->sctlr_el1 = read_sysreg(ARM64_SCTLR_EL1);
	context->hcr_el2 = read_sysreg(ARM64_HCR_EL2);
	context->sp_el1 = read_sysreg(ARM64_SP_EL1);
	context->sp_el0 = read_sysreg(ARM64_SP_EL0);
	context->spsr_el1 = read_sysreg(ARM64_SPSR_EL1);
	context->far_el1 = read_sysreg(ARM64_FAR_EL1);
	context->actlr_el1 = read_sysreg(ARM64_ACTLR_EL1);
	context->tpidr_el1 = read_sysreg(ARM64_TPIDR_EL1);
	context->csselr = read_sysreg(ARM64_CSSELR_EL1);
	context->cpacr = read_sysreg(ARM64_CPACR_EL1);
	context->contextidr = read_sysreg(ARM64_CONTEXTIDR_EL1);
	context->tpidr_el0 = read_sysreg(ARM64_TPIDR_EL0);
	context->tpidrro_el0 = read_sysreg(ARM64_TPIDRRO_EL0);
	context->cntkctl = read_sysreg(ARM64_CNTKCTL_EL1);
	context->afsr0 = read_sysreg(ARM64_AFSR0_EL1);
	context->afsr1 = read_sysreg(ARM64_AFSR1_EL1);

	if (task_is_32bit(vcpu->task)) {
		//context->teecr = read_sysreg32(TEECR32_EL1);
		//context->teehbr = read_sysreg32(TEEHBR32_EL1);
		context->dacr32_el2 = read_sysreg32(ARM64_DACR32_EL2);
		context->ifsr32_el2 = read_sysreg32(ARM64_IFSR32_EL2);
	}
}

static void aarch64_system_state_restore(struct vcpu *vcpu, void *c)
{
	struct aarch64_system_context *context =
			(struct aarch64_system_context *)c;

	write_sysreg(context->vbar_el1, VBAR_EL1);
	write_sysreg(context->esr_el1, ESR_EL1);
	write_sysreg(context->elr_el1, ELR_EL1);
	write_sysreg(context->vmpidr, VMPIDR_EL2);
	write_sysreg(context->vpidr, VPIDR_EL2);
	write_sysreg(context->sctlr_el1, SCTLR_EL1);
	write_sysreg(context->hcr_el2, HCR_EL2);
	write_sysreg(context->sp_el1, SP_EL1);
	write_sysreg(context->sp_el0, SP_EL0);
	write_sysreg(context->spsr_el1, SPSR_EL1);
	write_sysreg(context->far_el1, FAR_EL1);
	write_sysreg(context->actlr_el1, ACTLR_EL1);
	write_sysreg(context->tpidr_el1, TPIDR_EL1);
	write_sysreg(context->csselr, CSSELR_EL1);
	write_sysreg(context->cpacr, CPACR_EL1);
	write_sysreg(context->contextidr, CONTEXTIDR_EL1);
	write_sysreg(context->tpidr_el0, TPIDR_EL0);
	write_sysreg(context->tpidrro_el0, TPIDRRO_EL0);
	write_sysreg(context->cntkctl, CNTKCTL_EL1);
	write_sysreg(context->afsr0, AFSR0_EL1);
	write_sysreg(context->afsr1, AFSR1_EL1);

	if (task_is_32bit(vcpu->task)) {
		//write_sysreg(context->teecr, TEECR32_EL1);
		//write_sysreg(context->teehbr, TEEHBR32_EL1);
		write_sysreg(context->dacr32_el2, DACR32_EL2);
		write_sysreg(context->ifsr32_el2, IFSR32_EL2);
	}

	dsb();
}

static int aarch64_system_init(struct vmodule *vmodule)
{
	vmodule->context_size = sizeof(struct aarch64_system_context);
	vmodule->state_init = aarch64_system_state_init;
	vmodule->state_save = aarch64_system_state_save;
	vmodule->state_restore = aarch64_system_state_restore;
	vmodule->state_resume = aarch64_system_state_resume;

	return 0;
}
MINOS_MODULE_DECLARE(aarch64_system,
	AARCH64_SYSTEM_VMODULE, (void *)aarch64_system_init);

static int arm_create_vm(void *item, void *context)
{
	struct vm *vm = item;
	struct arm_virt_data *arch_data;

	arch_data = zalloc(sizeof(struct arm_virt_data));
	if (!arch_data)
		panic("No more memory for arm arch data\n");
	vm->arch_data = arch_data;

	return 0;
}

static int arm_virt_init(void)
{
	register_hook(arm_create_vm, OS_HOOK_CREATE_VM);

	return 0;
}
module_initcall(arm_virt_init);
