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

int arch_host_unmap(struct vspace *mm, unsigned long start,
		unsigned long end, int mode);

unsigned long arch_kernel_pgd_base(void);

int arch_get_asid_size(void);

int arch_host_change_map(struct vspace *vs, unsigned long vir,
		unsigned long phy, unsigned long flags);

pgd_t *arch_alloc_process_page_table(void);

void arch_task_sched_out(struct task *task);
void arch_task_sched_in(struct task *task);

void arch_set_task_user_stack(struct task *task, unsigned long stack);
void arch_set_task_reg0(struct task *task, unsigned long data);
void arch_set_tls(struct task *task, unsigned long tls);
void arch_set_task_entry_point(struct task *task, long entry);

#ifdef CONFIG_VIRT
struct mm_struct;

void *arch_alloc_guest_pgd(void);

int arch_guest_unmap(struct mm_struct *mm, unsigned long start, unsigned long end);

int arch_guest_map(struct mm_struct *mm, unsigned long start, unsigned long end,
		unsigned long physical, unsigned long flags);

int arch_translate_guest_ipa(struct mm_struct *vs, unsigned long va, phy_addr_t *pa);

#endif

#endif
