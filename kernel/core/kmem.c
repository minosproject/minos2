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
#include <minos/slab.h>
#include <minos/memory.h>
#include <minos/of.h>

struct kmem_section {
	void *pbase;
	void *vbase;
	size_t size;

	void *free_base;
	void *free_page_base;
	size_t free_size;
};

extern void add_kernel_page_section(phy_addr_t base,
		size_t size, int type);

static struct kmem_section kmem_section;
static struct kmem_section *ks;

static inline void *alloc_kpages_from_section(int pages)
{
	size_t request_size = pages << PAGE_SHIFT;
	void *base = NULL;

	ks->free_page_base -= request_size;
	base = ks->free_page_base;
	ks->free_size -= request_size;

	return base;
}

void *alloc_kpages(int pages)
{
	ASSERT(pages >= 0);
	return alloc_kpages_from_section(pages);
}

static inline void *alloc_kmem_from_section(size_t size)
{
	void *base = base;

	ASSERT(ks->free_size >= size);
	base = ks->free_base;
	ks->free_base += size;
	ks->free_size -= size;

	return base;
}

/*
 * kmem will not be freed once it has been allocated
 * kmem also can alloc small slab and one page, and
 * kmem will only used at the boot stage when the irq
 * and scheduler is disabled so there is no spin lock needed
 * when alloc kmem
 */
void *alloc_kmem(size_t size)
{
	size_t request_size = BALIGN(size, sizeof(unsigned long));

	return alloc_kmem_from_section(request_size);
}

void *zalloc_kmem(size_t size)
{
	void *base;

	ASSERT(size != 0);
	size = BALIGN(size, sizeof(unsigned long));

	base = alloc_kmem(size);
	if (base)
		memset(base, 0, size);

	return base;
}

void add_kmem_section(struct memory_region *region)
{
	if (ks != NULL) {
		pr_err("mutiple kernel memory section ?\n");
		return;
	}

	/*
	 * set the kernel memory section pointer.
	 */
	ks = &kmem_section;
	ks->pbase = (void *)region->phy_base;
	ks->vbase = (void *)ptov(ks->pbase);
	ks->size = region->size;
	ks->free_page_base = ks->vbase + ks->size;

	if (region->phy_base == minos_start) {
		ks->free_base = (void *)ptov(minos_end);
		ks->free_size = ks->size - (minos_end - minos_start);
	} else {
		ks->free_base = ks->vbase;
		ks->free_size = ks->size;
	}

	if (ks->free_page_base == ks->free_base) {
		pr_warn("skip wrong kmem section [0x%x 0x%x]\n",
				ks->pbase, ks->pbase + ks->size);
		return;
	}

	ASSERT(ks->free_page_base > ks->free_base);
	pr_notice("kmem [0x%x 0x%x]\n", ks->free_base,
			ks->free_base + ks->free_size);
}

void kmem_init(void)
{
	unsigned long base, size;

	base = PAGE_BALIGN(ks->free_base);
	size = (unsigned long)ks->free_page_base - base;

	add_kernel_page_section(vtop(base), size, 0);
}
