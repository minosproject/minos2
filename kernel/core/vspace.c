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
#include <minos/poll.h>

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

static void release_vspace_pages(struct vspace *vs)
{
	struct page *page = vs->release_pages;
	struct page *tmp;

	while (page) {
		tmp = page->next;
		__free_pages(page);
		page = tmp;
	}

	vs->release_pages = NULL;
}

void add_released_page_to_vspace(struct vspace *vs, unsigned long addr)
{
	struct page *page = addr_to_page(addr);

	ASSERT(page != NULL);
	page->next = vs->release_pages;
	vs->release_pages = page;
}

void inc_vspace_usage(struct vspace *vs)
{
	atomic_inc(&vs->inuse);
}

void dec_vspace_usage(struct vspace *vs)
{
	int value;

	value = atomic_dec_return(&vs->inuse);
	ASSERT(value >=0);
	if (value != 0)
		return;

	/*
	 * it is safe to release the pages here ? need double
	 * check.
	 */
	spin_lock(&vs->lock);
	if (atomic_read(&vs->inuse) != 0) {
		spin_unlock(&vs->lock);
		return;
	}

	release_vspace_pages(vs);
	spin_unlock(&vs->lock);
}

int create_host_mapping(unsigned long vir, unsigned long phy,
		size_t size, unsigned long flags)
{
	int ret;

	if (!IS_PAGE_ALIGN(vir) || !IS_PAGE_ALIGN(phy) ||
			!IS_PAGE_ALIGN(size))
		return -EINVAL;

	spin_lock(&host_vspace.lock);
	ret = arch_host_map(&host_vspace, __va(vir), __va(vir + size),
			phy, flags | VM_HOST | VM_HUGE);
	spin_unlock(&host_vspace.lock);

	return ret;
}

int destroy_host_mapping(unsigned long vir, size_t size)
{
	int ret;

	if (!IS_PAGE_ALIGN(vir) || !IS_PAGE_ALIGN(size))
		return -EINVAL;

	spin_lock(&host_vspace.lock);
	ret = arch_host_unmap(&host_vspace, __va(vir),
			__va(vir + size), UNMAP_RELEASE_NULL);
	spin_unlock(&host_vspace.lock);

	return ret;
}

int change_host_mapping(unsigned long vir, unsigned long phy,
		unsigned long new_flags)
{
	int ret;

	spin_lock(&host_vspace.lock);
	ret = arch_host_change_map(&host_vspace, __va(vir),
		       phy, new_flags | VM_HOST);
	spin_unlock(&host_vspace.lock);

	return ret;
}

unsigned long translate_va_to_pa(struct vspace *vs, unsigned long va)
{
	unsigned long addr;

	spin_lock(&vs->lock);
	addr = (unsigned long)arch_translate_va_to_pa(vs, va);
	spin_unlock(&vs->lock);

	return addr;
}

void *uva_to_kva(struct vspace *vs, unsigned long va,
		size_t size, unsigned long right)
{
	return (void *)translate_va_to_pa(vs, va);
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
	unsigned long start, end;
	int ret;

	vir = __va(vir);
	start = PAGE_ALIGN(vir);
	end = PAGE_BALIGN(vir + size);

	spin_lock(&host_vspace.lock);
	ret = arch_host_unmap(&host_vspace, start, end, UNMAP_RELEASE_NULL);
	spin_unlock(&host_vspace.lock);

	return ret;
}

static inline int __map_process_memory(struct vspace *vs, unsigned long vaddr,
		unsigned long end, unsigned long phy, unsigned long flags)
{
	int ret;

#if defined(CONFIG_VIRT) && !defined(CONFIG_ARM_VHE)
	ret = arch_guest_map(vs, vaddr, end, phy, flags);
	if (ret)
		arch_guest_unmap(vs, vaddr, end, UNMAP_RELEASE_PAGE_TABLE);
#else
	ret = arch_host_map(vs, vaddr, end, phy, flags);
	if (ret)
		arch_host_unmap(vs, vaddr, end, UNMAP_RELEASE_PAGE_TABLE);
#endif
	return ret;
}

int map_process_memory(struct process *proc, unsigned long vaddr,
		       size_t size, unsigned long phy, unsigned long flags)
{
	unsigned long end = vaddr + size;
	struct vspace *vs = &proc->vspace;
	int ret;

	if (!IS_PAGE_ALIGN(vaddr) || !IS_PAGE_ALIGN(phy) ||
			!IS_PAGE_ALIGN(size))
		return -EINVAL;

	spin_lock(&vs->lock);
	ret = __map_process_memory(vs, vaddr, end, phy, flags);
	spin_unlock(&vs->lock);

	return ret;
}

int unmap_process_memory(struct process *proc,
		unsigned long vaddr, size_t size)
{
	struct vspace *vs = &proc->vspace;
	int ret, inuse;

	if (!IS_PAGE_ALIGN(vaddr) || !IS_PAGE_ALIGN(size))
		return -EINVAL;

	/*
	 * cpu1: inc_vspace_usage
	 *       spin_lock
	 *       translate_va_to_pa
	 *
	 * cpu2 spin_lock
	 *      atomic_read
	 *      arch_host_unmap
	 *
	 * inuse value need after spin_lock.
	 */
	spin_lock(&vs->lock);
	inuse = atomic_read(&vs->inuse);
	ret = arch_host_unmap(&proc->vspace, vaddr, vaddr + size, UNMAP_RELEASE_ALL);
	if (inuse == 0)
		release_vspace_pages(vs);
	spin_unlock(&vs->lock);

	return ret;
}

static int __map_process_page_internal(struct process *proc,
		unsigned long virt, int write, unsigned long flags)
{
	struct vspace *vs = &proc->vspace;
	unsigned long phy;
	void *mem;
	int ret = 0;

	spin_lock(&vs->lock);

	/*
	 * if this virtual address has been already mapped
	 * just return 0
	 */
	phy = arch_translate_va_to_pa(vs, virt);
	if (phy != 0)
		goto out;

	mem = get_free_page(GFP_USER);
	if (mem == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	ret = __map_process_memory(vs, virt, virt + PAGE_SIZE, vtop(mem), VM_RWX);
	if (ret == -ENOMEM)
		free_pages(mem);
out:
	spin_unlock(&vs->lock);
	return ret;
}

static int handle_page_fault_internal(struct process *proc, unsigned long virt,
		int write, unsigned long flags)
{
	int ret;

	if ((virt < SYS_PROC_HEAP_BASE) || (virt >= SYS_PROC_HEAP_END)) {
		pr_err("access invalid address 0x%x [0x%x 0x%x]\n", virt,
				SYS_PROC_HEAP_BASE, SYS_PROC_HEAP_END);
		goto out;
	}

	ret = __map_process_page_internal(proc, virt, write, flags);
	if (ret)
		goto out;

	return 0;
out:
	process_die();

	/*
	 * will nerver get here.
	 */
	panic("kernel internal error when handle page fault\n");
	return -EFAULT;
}

static int handle_page_fault_ipc(struct process *proc, unsigned long virt,
		int write, unsigned long flags)
{
	uint64_t data[3];
	int ret;

	data[0] = virt;
	data[1] = write ? KOBJ_RIGHT_READ : KOBJ_RIGHT_WRITE;
	data[2] = current->tid;

	__event_task_wait(0, TASK_EVENT_ROOT_SERVICE, -1);

	/*
	 * send a poll_event to the root service to handle this
	 * page fault, and wait the root service to wake up
	 * it again.
	 */
	ret = poll_event_send_with_data(proc->kobj.poll_struct, POLLKERNEL,
				POLL_KEV_PAGE_FAULT, data[0], data[1], data[2]);
	if (ret)
		goto out;

	ret = wait_event();
	if (ret == 0)
		return 0;

out:
	process_die();
	return -EFAULT;
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

int vspace_init(struct process *proc)
{
	struct vspace *vs = &proc->vspace;

	spin_lock_init(&vs->lock);
	vs->pgdp = arch_alloc_process_page_table();
	if (!vs->pgdp)
		return -ENOMEM;

	vs->asid = allocate_asid();

	return 0;
}

void vspace_deinit(struct process *proc)
{
	struct vspace *vs = &proc->vspace;

	unmap_process_memory(proc, 0, USER_PROCESS_ADDR_LIMIT);

	if (vs->pgdp)
		free(vs->pgdp);
	if (vs->asid != 0)
		free_asid(vs->asid);
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
