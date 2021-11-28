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
#include <minos/uaccess.h>

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

int unmap_process_memory(struct process *proc, unsigned long vaddr, size_t size)
{
	struct vspace *vs = &proc->vspace;
	int ret, inuse;

	/*
	 * the process can be NULL when close the kobject
	 * by kernel, this is ok for kernel, since, kernel
	 * will unmap all the memory space for a process when
	 * the process exit.
	 */
	ASSERT(proc != NULL);
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
	asm volatile("ic ialluis" : : );
	if (inuse == 0)
		release_vspace_pages(vs);
	spin_unlock(&vs->lock);

	return ret;
}

static int __map_process_page_internal(struct process *proc,
		unsigned long virt, size_t size, unsigned long flags)
{
	struct vspace *vs = &proc->vspace;
	unsigned long phy;
	int ret = 0, i;
	void *mem;

	spin_lock(&vs->lock);

	for (i = 0; i < size >> PAGE_SHIFT; i++) {
		phy = arch_translate_va_to_pa(vs, virt);
		if (phy != 0) {
			pr_err("proc-%d 0x%x has been mapped\n", virt);
			continue;
		}

		mem = get_free_page(GFP_USER);
		if (mem == NULL) {
			ret = -ENOMEM;
			break;
		}

		ret = __map_process_memory(vs, virt, virt + PAGE_SIZE, vtop(mem), flags);
		if (ret) {
			free_pages(mem);
			break;
		}

		virt += PAGE_SIZE;
	}

	spin_unlock(&vs->lock);
	return ret;
}

static int handle_page_fault_internal(struct process *proc,
		unsigned long virt, int write)
{
	unsigned long flags = __VM_READ;
	int ret;

	if ((virt < SYS_PROC_HEAP_BASE) || (virt >= SYS_PROC_HEAP_END)) {
		pr_err("access invalid address 0x%x [0x%x 0x%x] 0x%x\n", virt,
				SYS_PROC_HEAP_BASE, SYS_PROC_HEAP_END,
				current->user_gp_regs->pc);
		goto out;
	}

	if (write)
		flags |= __VM_WRITE;

	ret = __map_process_page_internal(proc, virt, PAGE_SIZE, flags);
	if (ret)
		goto out;

	return 0;
out:
	process_die();
	panic("kernel internal error when handle page fault\n");

	return -EFAULT;
}

static int sys_map_anon(handle_t proc_handle, unsigned long virt,
		size_t size, right_t right)
{
	unsigned long flags = 0;
	struct kobject *kobj_proc;
	right_t right_proc;
	int ret;

	/*
	 * only root service can do the ANON mapping.
	 */
	if (!proc_is_root(current_proc))
		return -EPERM;

	if (!IS_PAGE_ALIGN(virt) || !IS_PAGE_ALIGN(size) || size == 0) {
		pr_err("%s invalid 0x%x 0x%x\n", virt, size);
		return -EINVAL;
	}

	if (right & KOBJ_RIGHT_READ)
		flags |= __VM_READ;
	if (right & KOBJ_RIGHT_WRITE)
		flags |= __VM_WRITE;
	if (right & KOBJ_RIGHT_EXEC)
		flags |= __VM_EXEC;

	ret = get_kobject(proc_handle, &kobj_proc, &right_proc);
	if (ret)
		return -ENOENT;

	ret =  __map_process_page_internal((struct process *)kobj_proc->data,
			virt, size, flags);
	put_kobject(kobj_proc);

	return ret;
}

static int sys_unmap_anon(handle_t proc_handle, unsigned long virt, size_t size)
{
	struct kobject *kobj;
	right_t right;
	int ret;

	if (!proc_is_root(current_proc))
		return -EPERM;

	ret = get_kobject(proc_handle, &kobj, &right);
	if (ret)
		return -ENOENT;

	ret = unmap_process_memory((struct process *)kobj->data, virt, size);
	put_kobject(kobj);

	return ret;
}

int sys_map(handle_t proc_handle, handle_t pma_handle,
		unsigned long virt, size_t size, right_t right)
{
	extern int sys_map_pma(handle_t proc_handle, handle_t pma_handle,
		unsigned long virt, size_t size, right_t right);

	if (!user_ranges_ok((void *)virt, size))
		return -EFAULT;

	if (!proc_can_vmctl(current_proc))
		return -EPERM;

	if (!IS_PAGE_ALIGN(virt) || !IS_PAGE_ALIGN(size))
		return -EINVAL;

	if (pma_handle <= 0)
		return sys_map_anon(proc_handle, virt, size, right);
	else
		return sys_map_pma(proc_handle, pma_handle, virt, size, right);
}

int sys_unmap(handle_t proc_handle, handle_t pma_handle,
		unsigned long virt, size_t size)
{
	extern int sys_unmap_pma(handle_t proc_handle, handle_t pma_handle,
			unsigned long virt, size_t size);

	if (!user_ranges_ok((void *)virt, size))
		return -EFAULT;

	if (!proc_can_vmctl(current_proc))
		return -EPERM;

	if (!IS_PAGE_ALIGN(virt) || !IS_PAGE_ALIGN(size))
		return -EINVAL;

	if (pma_handle <= 0)
		return sys_unmap_anon(proc_handle, virt, size);
	else
		return sys_unmap_pma(proc_handle, pma_handle, virt, size);
}

static int handle_page_fault_ipc(struct process *proc, unsigned long virt, int write)
{
	uint64_t info = write ? KOBJ_RIGHT_READ : KOBJ_RIGHT_WRITE;

	return process_page_fault(proc, virt, info);
}

int handle_page_fault(unsigned long virt, int write, unsigned long fault_type)
{
	struct process *proc = current_proc;
	gp_regs *regs= current_regs;
	int ret;

	if (proc_is_root(proc))
		ret = handle_page_fault_internal(proc, virt, write);
	else
		ret = handle_page_fault_ipc(proc, virt, write);
	if (!ret)
		return 0;

	/*
	 * Can not handle this page fualt. Kill this process. TBD
	 */
	pr_fatal("page fault fail %s [0x%x@0x%x]\n",
			proc->head->name, regs->pc, virt);
	kill_process(proc, ret);

	return -EFAULT;
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
