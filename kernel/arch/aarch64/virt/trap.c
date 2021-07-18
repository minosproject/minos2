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

#include <asm/aarch64_helper.h>
#include <virt/vm.h>
#include <asm/trap.h>
#include <minos/minos.h>
#include <minos/smp.h>
#include <asm/reg.h>
#include <minos/sched.h>
#include <minos/irq.h>
#include <asm/svccc.h>
#include <virt/vdev.h>

static inline int taken_from_el1(uint64_t spsr)
{
	return ((spsr & 0xf) != AARCH64_SPSR_EL0t);
}

static inline void inject_virtual_data_abort(uint32_t esr_value)
{
	uint64_t hcr_el2 = read_sysreg(HCR_EL2) | HCR_EL2_VSE;

	write_sysreg(hcr_el2, HCR_EL2);
	write_sysreg(esr_value, ESR_EL1);
	wmb();
}

static int unknown_handler(gp_regs *reg)
{
	return 0;
}

static int wfi_wfe_handler(gp_regs *reg)
{
	vcpu_idle(get_current_vcpu());
	return 0;
}

static int mcr_mrc_cp15_handler(gp_regs *reg)
{
#if 0
	switch (esr_value & HSR_CP32_REGS_MASK) {
	case HSR_CPREG32(ACTLR):
		break;
	default:
		pr_notice("mcr_mrc_cp15_handler 0x%x\n", esr_value);
		break;
	}
#endif

	return 0;
}

static int mcrr_mrrc_cp15_handler(gp_regs *reg)
{
#if 0
	struct esr_cp64 *sysreg = (struct esr_cp64 *)&esr_value;
	unsigned long reg_value0, reg_value1;
	unsigned long reg_value;
	struct vcpu *vcpu = get_current_vcpu();
	struct arm_virt_data *arm_data = vcpu->vm->arch_data;

	switch (esr_value & HSR_CP64_REGS_MASK) {
	case HSR_CPREG64(CNTP_CVAL):
		break;

	/* for aarch32 vm and using gicv3 */
	case HSR_CPREG64(ICC_SGI1R):
	case HSR_CPREG64(ICC_ASGI1R):
	case HSR_CPREG64(ICC_SGI0R):
		if (!sysreg->read && arm_data->sgi1r_el1_trap) {
			reg_value0 = get_reg_value(reg, sysreg->reg1);
			reg_value1 = get_reg_value(reg, sysreg->reg2);
			reg_value = (reg_value1 << 32) | reg_value0;
			arm_data->sgi1r_el1_trap(vcpu, reg_value);
		}
		break;
	}
#endif
	return 0;
}

static int mcr_mrc_cp14_handler(gp_regs *reg)
{
	return 0;
}

static int ldc_stc_cp14_handler(gp_regs *reg)
{
	return 0;
}

static int access_simd_reg_handler(gp_regs *reg)
{
	return 0;
}

static int mcr_mrc_cp10_handler(gp_regs *reg)
{
	return 0;
}

static int mrrc_cp14_handler(gp_regs *reg)
{
	return 0;
}

static int illegal_exe_state_handler(gp_regs *reg)
{
	return 0;
}

static int __arm_svc_handler(gp_regs *reg, int smc)
{
	uint32_t id;
	unsigned long args[6];

	id = reg->x0;
	args[0] = reg->x1;
	args[1] = reg->x2;
	args[2] = reg->x3;
	args[3] = reg->x4;
	args[4] = reg->x5;
	args[5] = reg->x6;

	if (!(id & SVC_CTYPE_MASK))
		local_irq_enable();

	return do_svc_handler(reg, id, args, smc);
}

static int access_system_reg_handler(gp_regs *reg)
{
#if 0
	int ret = 0, reg_name;
	struct esr_sysreg *sysreg = (struct esr_sysreg *)&esr_value;
	uint32_t regindex = sysreg->reg;
	unsigned long reg_value = 0;
	struct vcpu *vcpu = get_current_vcpu();
	struct arm_virt_data *arm_data = vcpu->vm->arch_data;

	reg_name = esr_value & ESR_SYSREG_REGS_MASK;
	if (!sysreg->read)
		reg_value = get_reg_value(reg, regindex);

	switch (reg_name) {
	case ESR_SYSREG_ICC_SGI1R_EL1:
	case ESR_SYSREG_ICC_ASGI1R_EL1:
	case ESR_SYSREG_ICC_SGI0R_EL1:
		pr_debug("access system reg SGI1R_EL1\n");
		if (!sysreg->read && (arm_data->sgi1r_el1_trap))
			arm_data->sgi1r_el1_trap(vcpu, reg_value);
		break;
	case ESR_SYSREG_CNTPCT_EL0:
	case ESR_SYSREG_CNTP_TVAL_EL0:
	case ESR_SYSREG_CNTP_CTL_EL0:
	case ESR_SYSREG_CNTP_CVAL_EL0:
		if (arm_data->phy_timer_trap) {
			ret = arm_data->phy_timer_trap(vcpu, reg_name,
					sysreg->read, &reg_value);
		}
		break;

	case ESR_SYSREG_DCZVA:
		if ((arm_data->dczva_trap) && !sysreg->read)
			ret = arm_data->dczva_trap(vcpu, reg_value);
		break;
	default:
		pr_debug("unsupport register access 0x%x %s\n",
				reg_name, sysreg->read ? "read" : "write");
		if (arm_data->sysreg_emulation) {
			ret = arm_data->sysreg_emulation(vcpu,
					reg_name, sysreg->read, &reg_value);
		}
		break;
	}

	if (sysreg->read)
		set_reg_value(reg, regindex, reg_value);
#endif
	return 0;
}

static int insabort_tfl_handler(gp_regs *reg)
{
	return 0;
}

static int misaligned_pc_handler(gp_regs *reg)
{
	return 0;
}

static int dataabort_tfl_handler(gp_regs *regs)
{
#if 0
	int ret;
	unsigned long vaddr;
	unsigned long paddr;
	unsigned long value;
	struct esr_dabt *dabt = (struct esr_dabt *)&esr_value;
	int dfsc = dabt->dfsc & ~FSC_LL_MASK;

	vaddr = read_sysreg(FAR_EL2);
	if (dabt->s1ptw || (dfsc == FSC_FLT_TRANS))
		paddr = get_faulting_ipa(vaddr);
	else
		paddr = guest_va_to_ipa(vaddr, 1);

	/*
	 * dfsc contain the fault type of the dataabort
	 * now only handle translation fault
	 */
	switch (dfsc) {
	case FSC_FLT_PERM:
	case FSC_FLT_TRANS:
		if (dabt->write)
			value = get_reg_value(regs, dabt->reg);

		ret = vdev_mmio_emulation(regs, dabt->write, paddr, &value);
		if (ret) {
			pr_warn("handle mmio read/write fail 0x%x vmid:%d\n",
					paddr, get_vmid(get_current_vcpu()));
			/*
			 * if failed to handle the mmio trap inject a
			 * sync error to guest vm to generate a fault
			 */
			inject_virtual_data_abort(esr_value);
		} else {
			if (!dabt->write)
				set_reg_value(regs, dabt->reg, value);
		}
		break;

	case FSC_FLT_ACCESS:
	default:
		pr_notice("unsupport data abort type %d @0x%p\n",
				dabt->dfsc & ~FSC_LL_MASK, paddr);
		inject_virtual_data_abort(esr_value);
		break;
	}
#endif
	return 0;
}

static int stack_misalign_handler(gp_regs *reg)
{
	return 0;
}

static int floating_aarch32_handler(gp_regs *reg)
{
	return 0;
}

static int floating_aarch64_handler(gp_regs *reg)
{
	return 0;
}

static int serror_handler(gp_regs *reg)
{
	return 0;
}

# if 0
static void populate_vcpu_fault_info(struct vcpu *vcpu)
{
	uint64_t hpfar;
	uint64_t esr;
	uint64_t far;

	esr = vcpu->fault.esr_el2;
	far = read_sysreg(FAR_EL2);

	if (!(esr & ESR_ELx_S1PTW) && ((esr & ESR_ELx_FSC_TYPE) == FSC_FLT_PERM))
		hpfar = guest_va_to_ipa(far, 1);
	else
		hpfar = read_sysreg(HPFAR_EL2);

	vcpu->fault.esr_el2 = esr;
	vcpu->fault.far_el2 = far;
	vcpu->fault.hpfar_el2 = hpfar;
}
#endif

static inline unsigned long get_vcpu_fault_type(struct vcpu *vcpu)
{
	return vcpu->fault.esr_el2 & ESR_ELx_FSC;
}

static inline unsigned long get_vcpu_fault_ipa(struct vcpu *vcpu)
{
	return ((unsigned long)vcpu->fault.hpfar_el2 & HPFAR_MASK) << 8;
}

static inline bool vcpu_fault_is_iabt(struct vcpu *vcpu)
{
	return ((unsigned long)(vcpu->fault.esr_el2 & ESR_ELx_EC_MASK) >> EC_INSABORT_TFL);
}

int aarch64_hypercall_handler(gp_regs *reg)
{
	struct vcpu *vcpu = get_current_vcpu();
	struct arm_virt_data *arm_data = vcpu->vm->arch_data;

	if (arm_data->hvc_handler)
		return arm_data->hvc_handler(vcpu, reg, read_esr_el2());
	else
		return __arm_svc_handler(reg, 0);
}

/* type defination is at armv8-spec 1906 */
DEFINE_SYNC_DESC(guest_EC_WFI_WFE, EC_TYPE_BOTH, wfi_wfe_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_UNKNOWN, EC_TYPE_BOTH, unknown_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_MCR_MRC_CP15, EC_TYPE_BOTH, mcr_mrc_cp15_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_MCRR_MRRC_CP15, EC_TYPE_AARCH32, mcrr_mrrc_cp15_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_MCR_MRC_CP14, EC_TYPE_AARCH32, mcr_mrc_cp14_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_LDC_STC_CP14, EC_TYPE_AARCH32, ldc_stc_cp14_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_ACCESS_SIMD_REG, EC_TYPE_BOTH, access_simd_reg_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_MCR_MRC_CP10, EC_TYPE_AARCH32, mcr_mrc_cp10_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_MRRC_CP14, EC_TYPE_AARCH32, mrrc_cp14_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_ILLEGAL_EXE_STATE, EC_TYPE_BOTH, illegal_exe_state_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_ACESS_SYSTEM_REG, EC_TYPE_AARCH64, access_system_reg_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_INSABORT_TFL, EC_TYPE_BOTH, insabort_tfl_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_MISALIGNED_PC, EC_TYPE_BOTH, misaligned_pc_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_DATAABORT_TFL, EC_TYPE_BOTH, dataabort_tfl_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_STACK_MISALIGN, EC_TYPE_BOTH, stack_misalign_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_FLOATING_AARCH32, EC_TYPE_AARCH32, floating_aarch32_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_FLOATING_AARCH64, EC_TYPE_AARCH64, floating_aarch64_handler, 1, 4);
DEFINE_SYNC_DESC(guest_EC_SERROR, EC_TYPE_BOTH, serror_handler, 1, 4);

static struct sync_desc *guest_sync_descs[] = {
	[0 ... MAX_SYNC_TYPE]	= &sync_desc_guest_EC_UNKNOWN,
	[EC_WFI_WFE]		= &sync_desc_guest_EC_WFI_WFE,
	[EC_MCR_MRC_CP15]       = &sync_desc_guest_EC_MCR_MRC_CP15,
	[EC_MCRR_MRRC_CP15]     = &sync_desc_guest_EC_MCRR_MRRC_CP15,
	[EC_MCR_MRC_CP14]       = &sync_desc_guest_EC_MCR_MRC_CP14,
	[EC_LDC_STC_CP14]       = &sync_desc_guest_EC_LDC_STC_CP14,
	[EC_ACCESS_SIMD_REG]    = &sync_desc_guest_EC_ACCESS_SIMD_REG,
	[EC_MCR_MRC_CP10]       = &sync_desc_guest_EC_MCR_MRC_CP10,
	[EC_MRRC_CP14]		= &sync_desc_guest_EC_MRRC_CP14,
	[EC_ILLEGAL_EXE_STATE]	= &sync_desc_guest_EC_ILLEGAL_EXE_STATE,
	[EC_ACESS_SYSTEM_REG]	= &sync_desc_guest_EC_ACESS_SYSTEM_REG,
	[EC_INSABORT_TFL]       = &sync_desc_guest_EC_INSABORT_TFL,
	[EC_MISALIGNED_PC]      = &sync_desc_guest_EC_MISALIGNED_PC,
	[EC_DATAABORT_TFL]      = &sync_desc_guest_EC_DATAABORT_TFL,
	[EC_STACK_MISALIGN]     = &sync_desc_guest_EC_STACK_MISALIGN,
	[EC_FLOATING_AARCH32]   = &sync_desc_guest_EC_FLOATING_AARCH32,
	[EC_FLOATING_AARCH64]   = &sync_desc_guest_EC_FLOATING_AARCH64,
	[EC_SERROR]		= &sync_desc_guest_EC_SERROR,
};

void handle_vcpu_sync_exception(gp_regs *regs)
{
	int cpuid = smp_processor_id();
	uint32_t esr_value;
	int ec_type;
	struct sync_desc *ec;
	struct vcpu *vcpu = get_current_vcpu();

	if ((!vcpu) || (vcpu->task->affinity != cpuid))
		panic("this vcpu is not belong to the pcpu");

	exit_from_guest(vcpu, regs);

	esr_value = read_esr_el2();
	vcpu->fault.esr_el2 = esr_value;
	ec_type = (esr_value & ESR_ELx_EC_MASK) >> ESR_ELx_EC_SHIFT;

	if (ec_type >= MAX_SYNC_TYPE) {
		pr_err("unknown sync exception type from guest %d\n", ec_type);
		goto out;
	}

	pr_debug("sync from lower EL, handle 0x%x\n", ec_type);
	ec = guest_sync_descs[ec_type];
	if (ec->irq_save)
		local_irq_enable();

	regs->pc += ec->ret_addr_adjust;
	ec->handler(regs);

out:
	local_irq_disable();
	enter_to_guest(vcpu, NULL);
}
