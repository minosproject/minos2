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
#include <minos/mm.h>
#include <asm/cpu_feature.h>

static struct vspace host_vspace;

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
			__va(vir + size), 0);
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
	ret = arch_host_unmap(&host_vspace, start, end, 0);
	spin_unlock(&host_vspace.lock);

	return ret;
}

void release_vspace_pages(struct vspace *vs)
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

static void host_unmap_range(struct vspace *vs, unsigned long start,
		unsigned long end, int flags)
{
	release_vspace_pages(vs);
}

static struct mm_notifier_ops host_mm_notifer_ops = {
	.unmap_range = host_unmap_range,
};

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
	vs->notifier_ops = &host_mm_notifer_ops;

	return 0;
}
