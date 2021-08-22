#ifndef __MINOS_ARCH_H_
#define __MINOS_ARCH_H_

#include <asm/arch.h>

struct vspace;
struct task;

#define raw_smp_processor_id()		arch_raw_smp_processor_id()

#define get_virtual_address_size()	arch_get_virtual_address_size()

phy_addr_t arch_translate_va_to_pa(struct vspace *mm, unsigned long va);

int arch_host_map(struct vspace *mm, unsigned long start, unsigned long end,
		unsigned long physical, unsigned long flags);

int arch_host_unmap(struct vspace *mm, unsigned long start, unsigned long end, int mode);

int arch_host_vspace_release(struct vspace *mm);

unsigned long arch_kernel_pgd_base(void);

int arch_host_change_map(struct vspace *vs, unsigned long vir,
		unsigned long phy, unsigned long flags);

pgd_t *arch_alloc_guest_pgd(void);

int arch_guest_vspace_release(struct vspace *vs);

int arch_guest_unmap(struct vspace *vs,
		unsigned long start,
		unsigned long end);

int arch_guest_map(struct vspace *vs,
		unsigned long start, unsigned long end,
		unsigned long physical, unsigned long flags);

phy_addr_t arch_translate_ipa_to_pa(struct vspace *vs, unsigned long va);

int arch_get_guest_huge_pmd(struct vspace *vs,
		unsigned long addr, pmd_t *pmd);

void arch_set_task_reg(struct task *task, int index, unsigned long value);

void arch_set_task_user_stack(struct task *task, unsigned long stack);

void arch_set_task_reg0(struct task *task, unsigned long data);

void arch_set_task_entry_point(struct task *task, long entry);

int arch_get_asid_size(void);

#endif
