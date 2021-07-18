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
#include <minos/vspace.h>
#include <minos/mm.h>
#include <asm/cpu_feature.h>
#include <minos/proc.h>
#include <minos/vspace.h>

#define MAX_ASID		4096
#define FIXED_SHARED_ASID	0
#define FIXED_KERNEL_ASID	1
#define USER_ASID_BASE		2

static struct vspace host_vspace;
static DECLARE_BITMAP(asid_bitmap, MAX_ASID);
static DEFINE_SPIN_LOCK(asid_lock);
static int max_asid;

static int allocate_asid(void)
{
	int asid = 0;

	if (max_asid <= USER_ASID_BASE)
		return 0;

	spin_lock(&asid_lock);
	asid = find_next_zero_bit(asid_bitmap, max_asid, USER_ASID_BASE);
	if (asid >= max_asid)
		asid = 0;
	else
		set_bit(asid, asid_bitmap);
	spin_unlock(&asid_lock);

	return asid;
}

static void free_asid(int asid)
{
	BUG_ON((asid >= max_asid) || (asid < USER_ASID_BASE));
	clear_bit(asid, asid_bitmap);
}

int create_host_mapping(unsigned long vir, unsigned long phy,
		size_t size, unsigned long flags)
{
	if (!IS_PAGE_ALIGN(vir) || !IS_PAGE_ALIGN(phy) ||
			!IS_PAGE_ALIGN(size))
		return -EINVAL;

	return arch_host_map(&host_vspace, __va(vir),
			__va(vir + size), phy,
			flags | VM_HOST | VM_HUGE);
}

int destroy_host_mapping(unsigned long vir, size_t size)
{
	if (!IS_PAGE_ALIGN(vir) || !IS_PAGE_ALIGN(size))
		return -EINVAL;

	return arch_host_unmap(&host_vspace, __va(vir), __va(vir + size));
}

int change_host_mapping(unsigned long vir, unsigned long phy,
		unsigned long new_flags)
{
       return arch_host_change_map(&host_vspace, __va(vir),
		       phy, new_flags | VM_HOST);
}

unsigned long translate_va_to_pa(struct vspace *vs, unsigned long va)
{
	return arch_translate_va_to_pa(vs, va);
}

void *uva_to_kva(struct vspace *vs, unsigned long va,
		size_t size, unsigned long right)
{
	/*
	 * TBD
	 */
	return (void *)pa2va(arch_translate_va_to_pa(vs, va));
}

void *io_remap(virt_addr_t vir, size_t size)
{
	size_t new_size;
	unsigned long start, end;

	end = PAGE_BALIGN(vir + size);
	start = PAGE_ALIGN(vir);
	new_size = end - vir;

	if (!create_host_mapping(start, vir, new_size, VM_IO | VM_RW))
		return (void *)ptov(vir);

	return NULL;
}

int io_unmap(virt_addr_t vir, size_t size)
{
	size_t new_size;
	unsigned long start, end;

	vir = __va(vir);
	end = PAGE_BALIGN(vir + size);
	start = PAGE_ALIGN(vir);
	new_size = end - start;

	return destroy_host_mapping((unsigned long)start, new_size);
}

int vspace_init(struct vspace *vs)
{
	spin_lock_init(&vs->lock);
	vs->pgdp = arch_alloc_process_page_table();
	if (!vs->pgdp)
		return -ENOMEM;

	vs->asid = allocate_asid();

	return 0;
}

void vspace_deinit(struct vspace *vs)
{
	if (vs->pgdp)
		free(vs->pgdp);
	if (vs->asid != 0)
		free_asid(vs->asid);
}


int access_ok(struct task *task, void *addr, size_t size, unsigned long flags)
{
	return 1;
}

int map_process_memory(struct process *proc,
		       unsigned long vaddr,
		       size_t size,
		       unsigned long phy,
		       unsigned long flags)
{
	unsigned long end = vaddr + size;
	int ret;

	if (!IS_PAGE_ALIGN(vaddr) || !IS_PAGE_ALIGN(phy) ||
			!IS_PAGE_ALIGN(size))
		return -EINVAL;

#if defined(CONFIG_VIRT) && !defined(CONFIG_ARM_VHE)
	ret = arch_guest_map(&proc->vspace, vaddr, end, phy, flags);
	if (ret)
		arch_guest_unmap(&proc->vspace, vaddr, end);
#else
	ret = arch_host_map(&proc->vspace, vaddr, end, phy, flags);
	if (ret)
		arch_host_unmap(&proc->vspace, vaddr, end);
#endif
	return ret;
}

int unmap_process_memory(struct process *proc,
		unsigned long vaddr, size_t size)
{
	if (!IS_PAGE_ALIGN(vaddr) || !IS_PAGE_ALIGN(size))
		return -EINVAL;

	return arch_host_unmap(&proc->vspace, vaddr, vaddr + size);	
}

static int handle_page_fault_internal(struct process *proc, unsigned long virt,
		int write, unsigned long flags)
{
	unsigned long phy;
	void *mem;

	if ((virt < SYS_PROC_HEAP_BASE) || (virt >= SYS_PROC_HEAP_END)) {
		pr_err("access invalid address 0x%x [0x%x 0x%x]\n", virt,
				SYS_PROC_HEAP_BASE, SYS_PROC_HEAP_END);
		panic("TBD\n");
	}

	/*
	 * only system process can be reached here, and only
	 * map the heap memory region.
	 */
	virt = PAGE_ALIGN(virt);
	phy = translate_va_to_pa(&proc->vspace, virt);
	ASSERT(phy == 0);

	mem = get_free_page(GFP_USER);
	ASSERT(mem != NULL);

	ASSERT(!map_process_memory(proc, virt, PAGE_SIZE, vtop(mem), VM_RWX));

	return 0;
}

static int handle_page_fault_ipc(struct process *proc, unsigned long virt,
		int write, unsigned long flags)
{
	return 0;
}


int handle_page_fault(unsigned long virt, int write, unsigned long flags)
{
	struct process *proc = current_proc;
	struct kobject *kobj = &proc->kobj;
	int ret;

	if (kobj->right & KOBJ_RIGHT_HEAP_SELFCTL)
		ret = handle_page_fault_internal(proc, virt, write, flags);
	else
		ret = handle_page_fault_ipc(proc, virt, write, flags);
	if (!ret)
		return 0;

	/*
	 * Can not handle this page fualt. Kill this process. TBD
	 */
	panic("page fault fail\n");

	return 0;

}

int kernel_vspace_init(void)
{
	struct vspace *vs = &host_vspace;

	/*
	 * init the host memory struct, the host will
	 * use va->pa mapping, but the mmio address will
	 * allocated a virtual range dynamicly
	 */
	spin_lock_init(&vs->lock);
	vs->pgdp = (pgd_t *)arch_kernel_pgd_base();

	max_asid = arch_get_asid_size();
	pr_info("max asid %d\n", max_asid);
	max_asid = max_asid > MAX_ASID ? MAX_ASID : max_asid;

	if (max_asid > USER_ASID_BASE) {
		bitmap_set(asid_bitmap, max_asid, BITMAP_SIZE(MAX_ASID));
		set_bit(FIXED_SHARED_ASID, asid_bitmap);
		set_bit(FIXED_KERNEL_ASID, asid_bitmap);
	}

	return 0;
}
