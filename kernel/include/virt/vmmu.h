#ifndef __MINOS_VIRT_VMMU_H__
#define __MINOS_VIRT_VMMU_H__

#include <minos/types.h>
#include <asm/vmmu.h>

typedef __vmm_pgd_t vmm_pgd_t;
typedef __vmm_pud_t vmm_pud_t;
typedef __vmm_pmd_t vmm_pmd_t;
typedef __vmm_pte_t vmm_pte_t;

#define VMM_PAGE_SIZE	__VMM_PAGE_SIZE
#define VMM_PAGE_SHIFT	__VMM_PAGE_SHIFT

#define VMM_PGD_RANGE_OFFSET		(__VMM_PGD_RANGE_OFFSET)
#define VMM_PGD_DES_OFFSET		(__VMM_PGD_DES_OFFSET)
#define VMM_PGD_ENTRY_OFFSET_MASK	(__VMM_PGD_ENTRY_OFFSET_MASK)

#define VMM_PUD_RANGE_OFFSET		(__VMM_PUD_RANGE_OFFSET)
#define VMM_PUD_DES_OFFSET		(__VMM_PUD_DES_OFFSET)
#define VMM_PUD_ENTRY_OFFSET_MASK	(__VMM_PUD_ENTRY_OFFSET_MASK)

#define VMM_PMD_RANGE_OFFSET		(__VMM_PMD_RANGE_OFFSET)
#define VMM_PMD_DES_OFFSET		(__VMM_PMD_DES_OFFSET)
#define VMM_PMD_ENTRY_OFFSET_MASK	(__VMM_PMD_ENTRY_OFFSET_MASK)

#define VMM_PTE_RANGE_OFFSET		(__VMM_PTE_RANGE_OFFSET)
#define VMM_PTE_DES_OFFSET		(__VMM_PTE_DES_OFFSET)
#define VMM_PTE_ENTRY_OFFSET_MASK	(__VMM_PTE_ENTRY_OFFSET_MASK)

#define VMM_PAGETABLE_ATTR_MASK 	(__VMM_PAGETABLE_ATTR_MASK)

#define VMM_PGD_MAP_SIZE		(1UL << VMM_PGD_RANGE_OFFSET)
#define VMM_PUD_MAP_SIZE		(1UL << VMM_PUD_RANGE_OFFSET)
#define VMM_PMD_MAP_SIZE		(1UL << VMM_PMD_RANGE_OFFSET)
#define VMM_PTE_MAP_SIZE		(1UL << VMM_PTE_RANGE_OFFSET)

#define VMM_PGD_SHIFT			VMM_PGD_RANGE_OFFSET
#define VMM_PUD_SHIFT			VMM_PUD_RANGE_OFFSET
#define VMM_PMD_SHIFT			VMM_PMD_RANGE_OFFSET
#define VMM_PTE_SHIFT			VMM_PTE_RANGE_OFFSET

#define VMM_PGD_MASK			(~(VMM_PGD_MAP_SIZE - 1))
#define VMM_PUD_MASK			(~(VMM_PUD_MAP_SIZE - 1))
#define VMM_PMD_MASK			(~(VMM_PMD_MAP_SIZE - 1))
#define VMM_PTE_MASK			(~(VMM_PTE_MAP_SIZE - 1))

#define VMM_PAGE_MAPPING_COUNT		(VMM_PAGE_SIZE / sizeof(pgd_t))
#define vmm_pgd_idx(vir)		((vir >> VMM_PGD_SHIFT) & (VMM_PAGE_MAPPING_COUNT - 1))
#define vmm_pud_idx(vir)		((vir >> VMM_PUD_SHIFT) & (VMM_PAGE_MAPPING_COUNT - 1))
#define vmm_pmd_idx(vir)		((vir >> VMM_PMD_SHIFT) & (VMM_PAGE_MAPPING_COUNT - 1))
#define vmm_pte_idx(vir)		((vir >> VMM_PTE_SHIFT) & (VMM_PAGE_MAPPING_COUNT - 1))

#define guest_pgd_idx(vir)		vmm_pgd_idx(vir)
#define guest_pud_idx(vir)		vmm_pud_idx(vir)
#define guest_pmd_idx(vir)		vmm_pmd_idx(vir)
#define guest_pte_idx(vir)		vmm_pte_idx(vir)

#define vmm_pgd_offset(ppgd, vir)	((pgd_t *)ppgd + vmm_pgd_idx(vir))
#define vmm_pud_offset(ppud, vir)	((pud_t *)ppud + vmm_pud_idx(vir))
#define vmm_pmd_offset(ppmd, vir)	((pmd_t *)ppmd + vmm_pmd_idx(vir))
#define vmm_pte_offset(ppte, vir)	((pte_t *)ppte + vmm_pte_idx(vir))

#define IS_VMM_PUD_ALIGN(x)		(!((unsigned long)(x) & (VMM_PUD_MAP_SIZE - 1)))
#define IS_VMM_PMD_ALIGN(x)		(!((unsigned long)(x) & (VMM_PMD_MAP_SIZE - 1)))

static inline size_t vmm_entry_map_size(size_t size, vir_addr_t vaddr, ems)
{
	size_t msize;

	msize = BALIGN(vaddr, ems) - vaddr;
	msize = msize ? msize : ems;

	return MIN(msize, size);
}

#define vmm_pgd_map_size(size, vaddr)	vmm_entry_map_size((size), (vaddr), VMM_PGD_MAP_SIZE)
#define vmm_pud_map_size(size, vaddr)	vmm_entry_map_size((size), (vaddr), VMM_PUD_MAP_SIZE)
#define vmm_pmd_map_size(size, vaddr)	vmm_entry_map_size((size), (vaddr), VMM_PMD_MAP_SIZE)

#define vmm_set_pte_at(ptep, off, p, attr) (*(pte_t *)ptep = val)
#define vmm_set_pmd_at(pmdp, off, p, attr) (*(pmd_t *)pmdp = val)
#define vmm_set_pud_at(pudp, off, p, attr) (*(pud_t *)pudp = val)
#define vmm_set_pgd_at(pgdp, off, p, attr) (*(pgd_t *)pgdp = val)

#define vmm_get_pmd(ppud) 		(vmm_pmd_t *)((*(vmm_pud_t *)ppud) & VMM_PAGETABLE_ATTR_MASK)

#define vmm_pgd_value(pgdp, off)	(*((pgd_t *)pgdp + off))
#define vmm_pud_value(pudp, off)	(*((pud_t *)pudp + off))
#define vmm_pmd_value(pmdp, off)	(*((pmd_t *)pmdp + off))

#endif
