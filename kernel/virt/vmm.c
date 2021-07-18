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

#include <minos/minos.h>
#include <virt/vm.h>
#include <minos/vspace.h>
#include <asm/tlb.h>
#include <asm/cache.h>

int create_guest_mapping(struct vspace *vs, vir_addr_t start,
		phy_addr_t phy, size_t size, unsigned long flags)
{
	unsigned long end;

	end = BALIGN(start + size, PAGE_SIZE);
	start = ALIGN(start, PAGE_SIZE);
	phy = ALIGN(phy, PAGE_SIZE);

	return arch_guest_map(vs, start, end, phy, flags | VM_HUGE_2M);
}

int destroy_guest_mapping(struct vspace *vs, unsigned long vir, size_t size)
{
	if (!IS_PAGE_ALIGN(vir) || !IS_PAGE_ALIGN(size)) {
		pr_warn("destroy guest mapping 0x%x->0x%x\n", vir, vir + size);
		return -EINVAL;
	}

	return arch_guest_unmap(vs, vir, vir + size);
}

static int vspace_area_map_ln(struct vspace *vs, struct vspace_area *va)
{
	return create_guest_mapping(vs, va->start, va->pstart, va->size, va->flags);
}

static int vspace_area_map_bk(struct vspace *vs, struct vspace_area *va)
{
	int ret;
	struct mem_block *block;
	unsigned long base = va->start;
	unsigned long size = va->size;

	list_for_each_entry(block, &va->b_head, list) {
		ret = create_guest_mapping(vs, base, block->phy_base,
				MEM_BLOCK_SIZE, va->flags | VM_HUGE_2M);
		if (ret)
			return ret;

		base += MEM_BLOCK_SIZE;
		size -= MEM_BLOCK_SIZE;

		if (size == 0)
			break;
	}

	return 0;
}

static inline int vspace_area_map_pg(struct vspace *vs, struct vspace_area *va)
{
	int ret;
	struct page *page = va->p_head;
	unsigned long base = va->start;
	unsigned long size = va->size;

	do {
		ret = create_guest_mapping(vs, base, page_pa(page), PAGE_SIZE, va->flags);
		if (ret)
			return ret;

		size -= PAGE_SIZE;
		page = page->next;

		if (page == NULL)
			break;
	} while (size > 0);

	return 0;
}

int map_vspace_area(struct vspace *vs, struct vspace_area *va, unsigned long pbase)
{
	va->pstart = pbase;

	switch (va->flags & VM_MAP_TYPE_MASK) {
	case VM_MAP_BK:
		vspace_area_map_bk(vs, va);
		break;
	case VM_MAP_PG:
		vspace_area_map_pg(vs, va);
		break;
	default:
		vspace_area_map_ln(vs, va);
		break;
	}

	return 0;
}

static void inline release_vspace_area_pg(struct vspace_area *va)
{
	struct page *page = va->p_head, *tmp;

	while (page != NULL) {
		tmp = page->next;
		release_pages(page);
		page = tmp;
	}
}

static void inline release_vspace_area_bk(struct vspace_area *va)
{
	struct mem_block *block, *n;

	list_for_each_entry_safe(block, n, &va->b_head, list) {
		release_mem_block(block);
		list_del(&block->list);
	}
}

static void release_vspace_area_in_vm0(struct vm *vm)
{
	struct vm *vm0 = get_vm_by_id(0);
	struct vspace *vs = &vm0->vs;
	struct vspace_area *va, *n;

	spin_lock(&vs->vspace_area_lock);

	list_for_each_entry_safe(va, n, &vs->vspace_area_used, list) {
		if (va->vmid != vm->vmid)
			continue;

		/*
		 * the kernel memory space for vm, mapped as NORMAL and
		 * PT attr, need to unmap it
		 */
		destroy_guest_mapping(&vm0->vs, va->start, va->size);

		if (!(va->flags & VM_SHARED))
			free((void *)va->pstart);

		list_del(&va->list);
		add_free_vspace_area(vs, va);
	}

	spin_unlock(&vs->vspace_area_lock);
}

static void release_vspace_area_memory(struct vspace_area *va)
{
	switch (va->flags & VM_MAP_TYPE_MASK) {
	case VM_MAP_BK:
		release_vspace_area_bk(va);
		break;
	case VM_MAP_PG:
		release_vspace_area_pg(va);
		break;
	default:
		if (va->pstart && !(va->flags & VM_PFNMAP) && !(va->flags & VM_SHARED))
			free((void *)va->pstart);
		break;
	}
}

void release_vm_memory(struct vm *vm)
{
	struct vspace *vs = &vm->vs;
	struct vspace_area *va, *n;

	/*
	 * first unmap the memory and clear the stage2
	 * page table
	 */
	arch_guest_vspace_release(vs);

	/*
	 * - release all the vspace_area and its memory
	 * - release the page table page and page table
	 * - set all the vspace to 0
	 * this function will not be called when vm is
	 * running, do not to require the lock
	 */
	list_for_each_entry_safe(va, n, &vs->vspace_area_used, list) {
		release_vspace_area_memory(va);
		list_del(&va->list);
		free(va);
	}

	list_for_each_entry_safe(va, n, &vs->vspace_area_free, list) {
		list_del(&va->list);
		free(va);
	}

	/*
	 * for guest vm, release the vm0's memory belong to this
	 * vm
	 */
	release_vspace_area_in_vm0(vm);
}

unsigned long create_hvm_iomem_map(struct vm *vm, unsigned long gbase,
		uint32_t size, unsigned long gflags)
{
	struct vspace_area *va;
	struct vm *vm0 = get_vm_by_id(0);
	void *iomem = NULL;

	va = alloc_vspace_area_page(&vm0->vs, size, gflags);
	if (!va)
		return INVALID_ADDR;

	size = PAGE_BALIGN(size);
	iomem = get_shared_pages(PAGE_NR(size), gflags);
	if (!iomem)
		return INVALID_ADDR;
	memset(iomem, 0, size);

	/*
	 * map the physical memory to the guest's virtual memory space
	 */
	if (gbase) {
		if (create_guest_mapping(&vm->vs, gbase,
				(unsigned long)iomem, size, gflags)) {
			free_pages(iomem);
			release_vspace_area(&vm0->vs, va);
			return INVALID_ADDR;
		}
	}

	va->vmid = vm->vmid;
	map_vspace_area(&vm0->vs, va, (unsigned long)iomem);

	return va->start;
}

/*
 * map VMx virtual memory to hypervisor memory
 * space to let hypervisor can access guest vm's
 * memory
 */
void *map_vm_mem(unsigned long gva, size_t size)
{
	unsigned long pa;

	/* assume the memory is continuously */
	pa = guest_va_to_pa(gva, 1);
	if (create_host_mapping(ptov(pa), pa, size, 0))
		return NULL;

	return (void *)ptov(pa);
}

void unmap_vm_mem(unsigned long gva, size_t size)
{
	unsigned long pa;

	/*
	 * what will happend if this 4k mapping is used
	 * in otherwhere
	 */
	pa = guest_va_to_pa(gva, 1);
	flush_dcache_range(ptov(pa), size);
	destroy_host_mapping(ptov(pa), size);
}

static int __vm_mmap(struct vspace *vs, unsigned long hvm_mmap_base,
		unsigned long offset, unsigned long size)
{
	struct vm *vm0 = get_vm_by_id(0);
	struct vspace *vs0 = &vm0->vs;
	unsigned long vir, phy;
	int ret, left;
	pmd_t pmd;

	if (!IS_HUGE_ALIGN(offset) || !IS_HUGE_ALIGN(hvm_mmap_base) ||
			!IS_HUGE_ALIGN(size)) {
		pr_err("__vm_vsap fail not PMD align 0x%p 0x%p 0x%x\n",
				hvm_mmap_base, offset, size);
		return -EINVAL;
	}

	vir = offset;
	phy = hvm_mmap_base;
	left = size >> HUGE_PAGE_SHIFT;

	while (left > 0) {
		ret = arch_get_guest_huge_pmd(vs, vir, &pmd);
		if (ret)
			return ret;

		ret = create_guest_mapping(vs0, phy, pmd, HUGE_PAGE_SIZE,
				VM_HUGE_2M | VM_NORMAL | VM_PFNMAP);
		if (ret)
			return ret;

		vir += HUGE_PAGE_SIZE;
		phy += HUGE_PAGE_SIZE;
		left--;
	}

	return 0;
}

/*
 * map the guest vm memory space to vm0 to let vm0 can access
 * the memory space of the guest VM, this function can only
 * map the normal memory for the guest VM, will not map IO
 * memory
 *
 * offset - the base address need to be mapped
 * size - the size need to mapped
 */
struct vspace_area *vm_mmap(struct vm *vm, unsigned long offset, size_t size)
{
	struct vspace_area *va;
	struct vm *vm0 = get_vm_by_id(0);

	/*
	 * allocate all the memory the GVM request but will not
	 * map all the memory, only map the memory which mvm request
	 * for linux, if it need use virtio then need to map all
	 * the memory, but for other os, may not require to map
	 * all the memory
	 */
	va = alloc_vspace_area_hugepage(&vm0->vs, size, VM_NORMAL | VM_PFNMAP);
	if (!va)
		return NULL;

	pr_info("%s start:0x%x size:0x%x\n", __func__, va->start, size);

	/*
	 * map all the guest vm's normal memory to the vm0's vspace
	 * so the vm0 can access all the physical memory of the guest
	 * vm, offset is the normal memory of the guest vm
	 */
	if (__vm_mmap(&vm->vs, va->start, offset, size)) {
		destroy_guest_mapping(&vm0->vs, va->start, va->size);
		release_vspace_area(&vm0->vs, va);
		pr_err("map guest vm memory to vm0 failed\n");
		return 0;
	}

	/* mark this vspace_area is for guest vm map */
	va->vmid = vm->vmid;

	return va;
}

static int __alloc_vm_memory(struct vspace *vs, struct vspace_area *va)
{
	int i, count;
	unsigned long base;
	struct mem_block *block;

	base = ALIGN(va->start, MEM_BLOCK_SIZE);
	if (base != va->start) {
		pr_warn("memory base is not mem_block align\n");
		return -EINVAL;
	}

	init_list(&va->b_head);
	va->flags |= VM_MAP_BK;
	count = va->size >> MEM_BLOCK_SHIFT;

	/*
	 * here get all the memory block for the vm
	 * TBD: get contiueous memory or not contiueous ?
	 */
	for (i = 0; i < count; i++) {
		block = alloc_mem_block(GFB_VM);
		if (!block)
			return -ENOMEM;

		list_add_tail(&va->b_head, &block->list);
	}

	return 0;
}

int alloc_vm_memory(struct vm *vm)
{
	struct vspace *vs = &vm->vs;
	struct vspace_area *va;

	list_for_each_entry(va, &vs->vspace_area_used, list) {
		if (!(va->flags & VM_NORMAL))
			continue;

		if (__alloc_vm_memory(vs, va))
			goto out;

		if (map_vspace_area(vs, va, 0))
			goto out;
	}

	return 0;

out:
	pr_err("alloc memory for vm-%d failed\n", vm->vmid);
	release_vm_memory(vm);
	return -ENOMEM;
}

phy_addr_t translate_vm_address(struct vm *vm, unsigned long a)
{
	return arch_translate_ipa_to_pa(&vm->vs, a);
}

static void vspace_area_init(struct vspace *vs, int bit64)
{
	unsigned long base, size;

	init_list(&vs->vspace_area_free);
	init_list(&vs->vspace_area_used);

	/*
	 * the virtual memory space for a virtual machine:
	 * 64bit - 40bit IPA size
	 * 32bit - 32bit IPA size (Without LPAE)
	 * 32bit - 40bit IPA size  (with LPAE)
	 */
	if (bit64) {
		base = 0x0;
		size = (unsigned long)1 << 40;
	} else {
#ifdef CONFIG_VM_LPAE
		base = 0x0;
		size = (unsigned long)1 << 40;
#else
		base = 0x0;
		size = 0x100000000;
#endif
	}

	create_free_vspace_area(vs, base, size, 0);
}

void vm_vspace_init(struct vm *vm)
{
	struct vspace *vs = &vm->vs;

	spin_lock_init(&vs->lock);
	spin_lock_init(&vs->vspace_area_lock);
	init_list(&vs->vspace_area_free);
	init_list(&vs->vspace_area_used);

	vs->pgdp = arch_alloc_guest_pgd();
	if (vs->pgdp == 0) {
		pr_err("No memory for vm page table\n");
		return;
	}

	vspace_area_init(vs, vm_is_64bit(vm));
}

int vm_mm_init(struct vm *vm)
{
	int ret;
	unsigned long base, end, size;
	struct vspace_area *va, *n;
	struct vspace *vs = &vm->vs;

	dump_vspace_areas(&vm->vs);

	/* just mapping the physical memory for native VM */
	list_for_each_entry(va, &vs->vspace_area_used, list) {
		if (!(va->flags & __VM_NORMAL))
			continue;

		ret = map_vspace_area(vs, va, va->start);
		if (ret) {
			pr_err("build mem mapping failed for vm-%d 0x%p 0x%p\n",
				vm->vmid, va->start, va->size);
		}
	}

	/*
	 * make sure that all the free vspace_area are PAGE aligned
	 */
	list_for_each_entry_safe(va, n, &vs->vspace_area_free, list) {
		base = BALIGN(va->start, PAGE_SIZE);
		end = ALIGN(VSPACE_AREA_END(va), PAGE_SIZE);
		size = end - base;

		if ((va->size < PAGE_SIZE) || (size == 0) || (base >= end)) {
			pr_debug("drop unused vspace_area 0x%p ---> 0x%p @0x%x\n",
					va->start, VSPACE_AREA_END(va) - 1, va->size);
			list_del(&va->list);
			free(va);
			continue;
		}

		if ((base != va->start) ||(size != va->size)) {
			pr_debug("adjust vspace_area: 0x%p->0x%p 0x%p->0x%p 0x%x->0x%x\n",
					va->start, base, VSPACE_AREA_END(va) - 1,
					end - 1, va->size, size);
			va->start = base;
			va->size = size;
		}
	}

	return 0;
}
