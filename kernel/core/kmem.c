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

#define MAX_KMEM_SECTION	8
static struct kmem_section kmem_sections[MAX_KMEM_SECTION];
static int kmem_section_cnt;
static DEFINE_SPIN_LOCK(kmem_lock);

static inline void *alloc_kpages_from_section(int pages)
{
	size_t request_size = pages << PAGE_SHIFT;
	struct kmem_section *ks;
	void *base = NULL;
	int i;

	spin_lock(&kmem_lock);

	for (i = 0; i < kmem_section_cnt; i++) {
		ks = &kmem_sections[i];
		if (ks->free_size < request_size)
			continue;

		ks->free_page_base -= request_size;
		base = ks->free_page_base;
		ks->free_size -= request_size;
	}

	spin_unlock(&kmem_lock);

	return base;
}

void *alloc_kpages(int pages)
{
	ASSERT(pages >= 0);

	return alloc_kpages_from_section(pages);
}

static inline void *alloc_kmem_from_section(size_t size)
{
	struct kmem_section *ks;
	void *base = base;
	int i;

	spin_lock(&kmem_lock);

	for (i = 0; i < kmem_section_cnt; i++) {
		ks = &kmem_sections[i];
		if (ks->free_size < size)
			continue;

		base = ks->free_base;
		ks->free_base += size;
		ks->free_size -= size;
		break;
	}

	spin_unlock(&kmem_lock);

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

static inline int in_os_memory_range(unsigned long addr, size_t size)
{
	return IN_RANGE_UNSIGNED(addr, size, minos_start, CONFIG_MINOS_RAM_SIZE);
}

static void add_kmem_section(struct memory_region *region)
{
	struct kmem_section *ks;

	if (kmem_section_cnt == MAX_KMEM_SECTION)
		return;

	ks = &kmem_sections[kmem_section_cnt];
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
	kmem_section_cnt++;

	pr_notice("kmem [0x%x 0x%x]\n", ks->free_base, ks->free_base + ks->free_size);
}

void kmem_init(void)
{
	struct memory_region *region;
	size_t kmem_size;
	int type;

	kmem_size = CONFIG_MINOS_RAM_SIZE - (minos_end - minos_start);
	if (!IS_PAGE_ALIGN(minos_end) || (kmem_size <= 0))
		panic("kmem: memory layout is wrong after boot\n");

	for_each_memory_region(region) {
		type = memory_region_type(region);
		if (type != MEMORY_REGION_TYPE_KERNEL)
			continue;

		if (in_os_memory_range(region->phy_base, region->size))
			add_kmem_section(region);
		else
			panic("Wrong kernel memory section [0x%x 0x%x]\n",
					region->phy_base,
					region->phy_base + region->size);
	}

	BUG_ON(kmem_section_cnt == 0, "Wrong memory configuration\n")
}
