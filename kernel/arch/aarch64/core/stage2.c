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
#include <minos/mm.h>
#include <asm/tlb.h>
#include <minos/vspace.h>
#include "stage2.h"

pgd_t *arch_alloc_guest_pgd(void)
{
	/*
	 * return the table base address, this function
	 * is called when init the vm
	 *
	 * 2 pages for each VM to map 1T IPA memory
	 *
	 */
	void *page;

	page = __get_free_pages(GUEST_PGD_PAGES,
			GUEST_PGD_PAGE_ALIGN, GFP_KERNEL);
	if (!page)
		panic("No memory to map vm memory\n");

	memset(page, 0, PAGE_SIZE * GUEST_PGD_PAGES);

	return page;
}

static inline uint64_t vspace_to_vttbr(struct vspace *vs)
{
	return (uint64_t)vs->pgdp | ((uint64_t)vs->asid << 48);
}

void flush_tlb_vm(struct vspace *vs)
{
	unsigned long flags;
	unsigned long old_vttbr = read_sysreg(VTTBR_EL2);
	unsigned long vttbr = vspace_to_vttbr(vs);

	local_irq_save(flags);

	write_sysreg(vttbr, VTTBR_EL2);

	flush_all_tlb_guest();

	write_sysreg(old_vttbr, VTTBR_EL2);

	local_irq_restore(flags);
}

static void inline flush_tlb_ipa_range(unsigned long va, size_t size)
{
	flush_tlb_ipa_guest(va, size);
}

void flush_tlb_vm_ipa_range(struct vspace *vs, unsigned long ipa, size_t size)
{
	unsigned long flags;
	unsigned long old_vttbr = read_sysreg(VTTBR_EL2);
	unsigned long vttbr = vspace_to_vttbr(vs);

	local_irq_save(flags);

	write_sysreg(vttbr, VTTBR_EL2);

	flush_tlb_ipa_range(ipa, size);

	write_sysreg(old_vttbr, VTTBR_EL2);

	local_irq_restore(flags);
}

static void inline stage2_pgd_clear(pud_t *pgdp)
{
	WRITE_ONCE(*pgdp, 0);
	__dsb(ishst);
	isb();
}

static void inline stage2_pud_clear(pud_t *pudp)
{
	WRITE_ONCE(*pudp, 0);
	__dsb(ishst);
	isb();
}

static void inline stage2_pmd_clear(pmd_t *pmdp)
{
	WRITE_ONCE(*pmdp, 0);
	__dsb(ishst);
	isb();
}

static unsigned long stage2_xxx_addr_end(unsigned long start,
		unsigned long end, size_t map_size)
{
	unsigned long boundary = (start + map_size) & ~((unsigned long)map_size - 1);

	return ((boundary - 1) < (end - 1)) ? boundary : end;
}

#define stage2_pgd_addr_end(start, end)	\
	stage2_xxx_addr_end(start, end, S2_PGD_SIZE)

#define stage2_pud_addr_end(start, end)	\
	stage2_xxx_addr_end(start, end, S2_PUD_SIZE)

#define stage2_pmd_addr_end(start, end)	\
	stage2_xxx_addr_end(start, end, S2_PMD_SIZE)

static inline void stage2_set_pte(pte_t *ptep, pte_t new_pte)
{
	WRITE_ONCE(*ptep, new_pte);
	__dsb(ishst);
}

static inline void stage2_set_pmd(pmd_t *pmdp, pmd_t new_pmd)
{
	WRITE_ONCE(*pmdp, new_pmd);
	__dsb(ishst);
}

static inline void stage2_set_pud(pud_t *pudp, pud_t new_pud)
{
	WRITE_ONCE(*pudp, new_pud);
	__dsb(ishst);
}

static inline void stage2_set_pgd(pgd_t *pgdp, pgd_t new_pgd)
{
	WRITE_ONCE(*pgdp, new_pgd);
	__dsb(ishst);
}

static inline void stage2_pgd_populate(pgd_t *pgdp, unsigned long addr)
{
	stage2_set_pgd(pgdp, addr | S2_DES_TABLE);
}

static inline void stage2_pud_populate(pud_t *pudp, unsigned long addr)
{
	stage2_set_pud(pudp, addr | S2_DES_TABLE);
}

static inline void stage2_pmd_populate(pmd_t *pmdp, unsigned long addr)
{
	stage2_set_pmd(pmdp, addr | S2_DES_TABLE);
}

static inline pmd_t stage2_pmd_attr(unsigned long phy, unsigned long flags)
{
	pmd_t pmd = phy & S2_PMD_MASK;

	switch (flags & VM_TYPE_MASK) {
	case __VM_NC:
		pmd |= S2_BLOCK_NC;
		break;
	case __VM_IO:
		pmd |= S2_BLOCK_DEVICE;
		break;
	case __VM_WC:
		pmd |= S2_BLOCK_WC;
		break;
	case __VM_WT:
		pmd |= S2_BLOCK_WT;
		break;
	default:
		pmd |= S2_BLOCK_NORMAL;
		break;
	}

	switch (flags & VM_RW_MASK) {
	case __VM_RO:
		pmd |= S2_AP_RO;
		break;
	case __VM_WO:
		pmd |= S2_AP_WO;
		break;
	case __VM_RW_NON:
		pmd |= S2_AP_NON;
		break;
	default:
		pmd |= S2_AP_RW;
		break;
	}

	if (flags & __VM_PFNMAP)
		pmd |= S2_PFNMAP;

	if (flags & __VM_DEVMAP)
		pmd |= S2_DEVMAP;

	return pmd;
}

static inline pte_t stage2_pte_attr(unsigned long phy, unsigned long flags)
{
	pte_t pte = phy & S2_PTE_MASK;

	switch (flags & VM_TYPE_MASK) {
	case __VM_NC:
		pte |= S2_PAGE_NC;
		break;
	case __VM_IO:
		pte |= S2_PAGE_DEVICE;
		break;
	case __VM_WC:
		pte |= S2_PAGE_WC;
		break;
	case __VM_WT:
		pte |= S2_PAGE_WT;
		break;
	default:
		pte |= S2_PAGE_NORMAL;
		break;
	}

	switch (flags & VM_RW_MASK) {
	case VM_RO:
		pte |= S2_AP_RO;
		break;
	case VM_WO:
		pte |= S2_AP_WO;
		break;
	case VM_RW_NON:
		pte |= S2_AP_NON;
		break;
	default:
		pte |= S2_AP_RW;
		break;
	}

	if (flags & __VM_PFNMAP)
		pte |= S2_PFNMAP;

	if (flags & __VM_DEVMAP)
		pte |= S2_DEVMAP;

	return pte;
}

static void stage2_unmap_pte_range(struct vspace *vs, pmd_t *pmd,
		unsigned long addr, unsigned long end)
{
	pte_t *ptep, *pte;

	ptep = stage2_pte_table_addr(*pmd);
	pte = stage2_pte_offset(ptep, addr);
	do {
		if (!stage2_pte_none(*pte)) {
			stage2_set_pte(pte, 0);
			flush_tlb_ipa_range(addr, PAGE_SIZE);
		}
	} while (pte++, addr += PAGE_SIZE, addr != end);
}

static void stage2_unmap_pmd_range(struct vspace *vs, pmd_t *pmdp,
		unsigned long addr, unsigned long end, int release)
{
	unsigned long next;
	pmd_t *pmd;
	pte_t *ptep;

	pmd = stage2_pmd_offset(pmdp, addr);

	do {
		next = stage2_pmd_addr_end(addr, end);
		if (!stage2_pmd_none(*pmd)) {
			if (stage2_pmd_huge(*pmd)) {
				stage2_pmd_clear(pmd);
				flush_tlb_ipa_range(addr, S2_PMD_SIZE);
			} else {
				ptep = stage2_pte_table_addr(*pmd);
				stage2_unmap_pte_range(vs, ptep, addr, next);

				if (release)
					free((void *)ptep);
			}
		}
	} while (pmd++, addr = next, addr != end);
}

static int stage2_unmap_pud_range(struct vspace *vs,
		unsigned long addr, unsigned long end, bool release)
{
	unsigned long next;
	pud_t *pud;
	pmd_t *pmdp;

	pud = stage2_pud_offset((pud_t *)vs->pgdp, end);
	do {
		next = stage2_pud_addr_end(addr, end);
		if (!stage2_pud_none(*pud)) {
			pmdp = stage2_pmd_table_addr(*pud);
			stage2_unmap_pmd_range(vs, pmdp, addr, next, release);

			if (release)
				free((void *)pmdp);
		}
	} while (pud++, addr = next, addr != end);

	return 0;
}

static int stage2_unmap_ipa_range(struct vspace *vs,
		unsigned long addr, unsigned long end, bool release)
{
	unsigned long old_vttbr = read_sysreg(VTTBR_EL2);
	unsigned long vttbr = vspace_to_vttbr(vs);
	int ret;

	/*
	 * switch to the VM vttbr to make sure the
	 * vttbr_el2 is use correct value
	 */
	write_sysreg(vttbr, VTTBR_EL2);
	wmb();
	isb();

	ret = stage2_unmap_pud_range(vs, addr, end, release);

	write_sysreg(old_vttbr, VTTBR_EL2);
	wmb();
	isb();

	return ret;
}

static int stage2_map_pte_range(struct vspace *vs, pte_t *ptep, unsigned long start,
		unsigned long end, unsigned long physical, unsigned long flags)
{
	unsigned long pte_attr;
	pte_t *pte;
	pte_t old_pte;

	pte = stage2_pte_offset(ptep, start);
	pte_attr = stage2_pte_attr(0, flags);

	do {
		old_pte = *pte;
		if (old_pte)
			pr_debug("address remaped 0x%lx: [0x%lx 0x%lx]\n",
					start, old_pte, pte_attr);
		if (old_pte != (pte_attr | physical))
			stage2_set_pte(pte, pte_attr | physical);
	} while (pte++, start += PAGE_SIZE, physical += PAGE_SIZE, start != end);

	return 0;
}

static inline bool stage2_pmd_huge_page(pmd_t old_pmd, unsigned long start,
		unsigned long phy, size_t size, unsigned long flags)
{
	if (!(flags & __VM_HUGE_2M) || old_pmd)
		return false;

	if (!IS_BLOCK_ALIGN(start) || !IS_BLOCK_ALIGN(phy) || !(IS_BLOCK_ALIGN(size)))
		return false;

	return true;
}

static int stage2_map_pmd_range(struct vspace *vs, pmd_t *pmdp, unsigned long start,
		unsigned long end, unsigned long physical, unsigned long flags)
{
	unsigned long next;
	pmd_t *pmd;
	pmd_t old_pmd;
	pte_t *ptep;
	size_t size;
	int ret;
	unsigned long attr;

	pmd = stage2_pmd_offset(pmdp, start);
	do {
		next = stage2_pmd_addr_end(start, end);
		size = next - start;
		old_pmd = *pmd;

		/*
		 * virtual memory need to map as PMD huge page
		 */
		if (stage2_pmd_huge_page(old_pmd, start, physical, size, flags)) {
			attr = stage2_pmd_attr(physical, flags);
			stage2_set_pmd(pmd, attr);
		} else {
			if (stage2_pmd_none(old_pmd)) {
				ptep = (pte_t *)get_free_page(GFP_KERNEL);
				if (!ptep)
					return -ENOMEM;
				memset(ptep, 0, PAGE_SIZE);
				stage2_pmd_populate(pmd, (unsigned long)ptep);
			} else {
				ptep = stage2_pte_table_addr(old_pmd);
			}

			ret = stage2_map_pte_range(vs, ptep, start, next, physical, flags);
			if (ret)
				return ret;
		}
	} while (pmd++, physical += size, start = next, start != end);

	return 0;
}

static int stage2_map_pud_range(struct vspace *vs, unsigned long start,
		unsigned long end, unsigned long physical, unsigned long flags)
{
	unsigned long next;
	pud_t *pud;
	pmd_t *pmdp;
	size_t size;
	int ret;

	pud = stage2_pud_offset((pud_t *)vs->pgdp, start);
	do {
		next = stage2_pud_addr_end(start, end);
		size = next - start;

		if (stage2_pud_none(*pud)) {
			pmdp = (pmd_t *)get_free_page(GFP_KERNEL);
			if (!pmdp)
				return -ENOMEM;
			memset(pmdp, 0, PAGE_SIZE);
			stage2_pud_populate(pud, (unsigned long)pmdp);
		} else {
			pmdp = stage2_pmd_table_addr(*pud);
		}

		ret = stage2_map_pmd_range(vs, pmdp, start, next, physical, flags);
		if (ret)
			return ret;
	} while (pud++, physical += size, start = next, start != end);

	return 0;
}

phy_addr_t stage2_ipa_to_pa(struct vspace *vs, unsigned long va)
{
	unsigned long pte_offset = va - (va & ~S2_PTE_MASK);
	unsigned long pmd_offset = va - (va & ~S2_PMD_MASK);
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;

	pudp = stage2_pud_offset(vs->pgdp, va);
	if (!stage2_pud_none(*pudp))
		return INVALID_ADDR;

	pmdp = stage2_pmd_offset(stage2_pmd_table_addr(*pudp), va);
	if (!stage2_pmd_none(*pmdp))
		return INVALID_ADDR;

	if (stage2_pmd_huge(*pmdp))
		return ((*pudp) & S2_PHYSICAL_MASK) + pmd_offset;

	ptep = stage2_pte_offset(stage2_pte_table_addr(*pmdp), va);

	return ((*ptep) & S2_PHYSICAL_MASK) + pte_offset;
}

static int stage2_get_huge_pmd(struct vspace *vs, unsigned long addr, pmd_t *pmd)
{
	pud_t *pudp;
	pmd_t *pmdp;

	pudp = stage2_pud_offset(vs->pgdp, addr);
	if (!stage2_pud_none(*pudp))
		return -ENOENT;

	pmdp = stage2_pmd_offset(stage2_pmd_table_addr(*pudp), addr);
	if (!stage2_pmd_none(*pmdp) && !stage2_pmd_huge(*pmdp))
		return -EINVAL;

	*pmd = (*pmdp) & S2_PHYSICAL_MASK;

	return 0;
}

int arch_get_guest_huge_pmd(struct vspace *vs, unsigned long addr, pmd_t *pmd)
{
	return stage2_get_huge_pmd(vs, addr, pmd);
}

phy_addr_t arch_translate_ipa_to_pa(struct vspace *vs, unsigned long va)
{
	return stage2_ipa_to_pa(vs, va);
}

int arch_guest_map(struct vspace *vs,
		unsigned long start, unsigned long end,
		unsigned long physical, unsigned long flags)
{
	return stage2_map_pud_range(vs, start, end, physical, flags);
}

int arch_guest_unmap(struct vspace *vs, unsigned long start, unsigned long end)
{
	return stage2_unmap_ipa_range(vs, start, end, 0);
}

int arch_guest_vspace_release(struct vspace *vs)
{
	if (vs->pgdp) {
		stage2_unmap_ipa_range(vs, 0, S2_PHYSICAL_SIZE, 1);
		free(vs->pgdp);
		vs->pgdp = NULL;
	}

	return 0;
}
