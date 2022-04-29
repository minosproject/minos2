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

#include <minos/types.h>
#include <config/config.h>
#include <minos/spinlock.h>
#include <minos/minos.h>
#include <minos/init.h>
#include <minos/mm.h>
#include <minos/vspace.h>
#include <minos/page.h>
#include <minos/slab.h>

extern void *alloc_kmem(size_t size);
extern void *zalloc_kmem(size_t size);
extern void *alloc_kpages(int pages);

#define __PAGE_F_KERNL		__GFP_KERNEL
#define __PAGE_F_USER		__GFP_USER
#define __PAGE_F_GUEST		__GFP_GUEST
#define __PAGE_F_DMA		__GFP_DMA
#define __PAGE_F_SLAB		__GFP_SLAB
#define __PAGE_F_SHARED		__GFP_SHARED
#define __PAGE_F_IO		__GFP_IO
#define __PAGE_F_HUGE		__GFP_HUGE

#define PAGE_F_KERNL		GFP_KERNEL
#define PAGE_F_USER		GFP_USER
#define PAGE_F_GUEST		GFP_GUEST
#define PAGE_F_DMA		GFP_DMA
#define PAGE_F_SLAB		GFP_SLAB
#define PAGE_F_SHARED		GFP_SHARED
#define PAGE_F_SHARED_IO	GFP_SHARED_IO
#define PAGE_F_HUGE		GFP_HUGE
#define PAGE_F_HUGE_IO		GFP_HUGE_IO
#define PAGE_F_HEAD		0x00000100
#define PAGE_F_MASK		0x0000ffff

#define MAX_MEM_SECTIONS 32

struct mem_section {
	int block_section;

	unsigned long phy_base;
	unsigned long vir_base;
	unsigned long vir_end;
	size_t size;

	size_t total_cnt;
	size_t free_cnt;
	unsigned long *bitmap;
	unsigned long bm_end;
	unsigned long bm_current;

	unsigned long *block_bitmap;
	size_t total_block;
	int current_block;
	size_t free_block;

	spinlock_t lock;

	struct page *pages;
};

#define PAGE_ADDR(base, bit)	((unsigned long)base + ((unsigned long)bit << PAGE_SHIFT))

/*
 * ID 0 will reserver for kernel memory section.
 */
static struct mem_section mem_sections[MAX_MEM_SECTIONS];
static int nr_sections = 1;

void add_kernel_page_section(phy_addr_t base, size_t size, int type)
{
	unsigned long end, new_size;
	size_t page_cnt;
	struct mem_section *ms = &mem_sections[0];

	memset(ms, 0, sizeof(struct mem_section));
	end = base + size;
	page_cnt = size >> PAGE_SHIFT;

	ms->bitmap = (unsigned long *)ptov(base);
	base += BITMAP_SIZE(page_cnt);
	memset(ms->bitmap, 0, BITMAP_SIZE(page_cnt));

	ms->pages = (struct page *)ptov(base);
	base += page_cnt * sizeof(struct page);
	memset(ms->pages, 0, page_cnt * sizeof(struct page));

	base = PAGE_BALIGN(base);
	new_size = end - base;

	spin_lock_init(&ms->lock);
	ms->phy_base = base;
	ms->vir_base = ptov(base);
	ms->size = new_size;
	ms->vir_end = ms->vir_base + ms->size;
	ms->total_cnt = new_size >> PAGE_SHIFT;
	ms->free_cnt = ms->total_cnt;
	ms->bm_current = 0;
	ms->bm_end = ms->total_cnt;

	pr_notice("boot memory section [0x%lx +0x%lx]\n", base, new_size);
}

int add_page_section(phy_addr_t base, size_t size, int type)
{
	struct mem_section *ms;
	int block_align = 1;

	if ((size == 0) || (nr_sections >= MAX_MEM_SECTIONS)) {
		pr_err("no enough memory section for page section\n");
		return -EINVAL;
	}

	if (!IS_BLOCK_ALIGN(base) || !IS_BLOCK_ALIGN(size))
		block_align = 0;

	pr_notice("umem [0x%x 0x%x] [%s] section\n", base, base + size,
			block_align ? "Block" : "Page");

	ms = &mem_sections[nr_sections];
	memset(ms, 0, sizeof(struct mem_section));
	spin_lock_init(&ms->lock);

	ms->phy_base = base;
	ms->vir_base = ptov(base);
	ms->size = size;
	ms->vir_end = ms->vir_base + ms->size;

	/*
	 * init the page informations.
	 */
	ms->total_cnt = size >> PAGE_SHIFT;
	ms->free_cnt = ms->total_cnt;
	ms->bitmap = alloc_kmem(BITMAP_SIZE(ms->total_cnt));
	ASSERT(ms->bitmap != NULL);

	memset(ms->bitmap, 0, BITMAP_SIZE(ms->total_cnt));
	ms->bm_current = 0;
	ms->bm_end = ms->total_cnt;

	/*
	 * just allocate the pages struct for this section
	 * but do not init the memory data to 0, since if the
	 * memory size is too big will slow down the boot time
	 */
	ms->pages = alloc_kmem(ms->total_cnt * sizeof(struct page));
	ASSERT(ms->pages != NULL);
	memset(ms->pages, 0, ms->total_cnt * sizeof(struct page));

	/*
	 * init the block information for this section, so
	 * can get 2M blocks from this section if needed.
	 */
	if (block_align) {
		ms->block_section = 1;
		ms->total_block = ms->size >> BLOCK_SHIFT;
		ms->free_block = ms->total_block;
		ms->block_bitmap = alloc_kmem(BITMAP_SIZE(ms->total_block));
		ASSERT(ms->block_bitmap != NULL);
		memset(ms->block_bitmap, 0, BITMAP_SIZE(ms->total_block));
	}

	nr_sections++;

	return 0;
}

static void alloc_pages_in_block(struct page *page, struct mem_section *ms)
{
	unsigned long start = page_pa(page);
	unsigned long base = ALIGN(start, BLOCK_SIZE);
	unsigned long end = BALIGN(start + page->cnt * PAGE_SIZE, BLOCK_SIZE);
	int size = ((end - base) >> PAGE_SHIFT) / PAGES_PER_BLOCK;

	start = (base - start) >> BLOCK_SHIFT;
	bitmap_set(ms->block_bitmap, start, size);
}

static void free_pages_in_block(struct page *page, struct mem_section *ms)
{
	int count = page_count(page);
	unsigned long tmp, start, end;
	unsigned long *baddr;
	int i, sum, bbit, pbit;
	
	tmp = page_pa(page);
	start = ALIGN(tmp, BLOCK_SIZE);
	end = BALIGN(tmp + count * PAGE_SIZE, BLOCK_SIZE);
	bbit = (start - ms->phy_base) >> BLOCK_SHIFT;
	pbit = (start - ms->phy_base) >> PAGE_SHIFT;

	/*
	 * clear the related bit in the block map if all
	 * the pages in this block has been freed.
	 */
	for (i = 0; i < (end - start) >> BLOCK_SHIFT; i++) {
		/*
		 * get the start page bit postion in page bitmap.
		 * the check whether all the bits are zero.
		 */
		baddr = ms->bitmap + BITS_TO_LONGS(pbit);
		sum = 0;
		sum += (baddr[0] != 0);
		sum += (baddr[1] != 0);
		sum += (baddr[2] != 0);
		sum += (baddr[3] != 0);
		sum += (baddr[4] != 0);
		sum += (baddr[5] != 0);
		sum += (baddr[6] != 0);
		sum += (baddr[7] != 0);

		if (sum == 0) {
			clear_bit(bbit, ms->block_bitmap);
			ms->free_block++;
		}

		pbit += PAGES_PER_BLOCK;
		bbit++;
	}
}

static struct mem_section *addr_to_mem_section(unsigned long addr)
{
	struct mem_section *temp;
	int i;

	for (i = 0; i < nr_sections; i++) {
		temp = &mem_sections[i];
		if ((addr >= temp->vir_base) && (addr < temp->vir_end))
			return temp;
	}

	return NULL;
}

static struct page *__alloc_pages_from_section(struct mem_section *section,
		int count, int align, int flags)
{
	struct page *page;
	int bit;

	if (count == 1)
		bit = find_next_zero_bit_loop(section->bitmap, section->total_cnt,
				section->bm_current);
	else
		bit = bitmap_find_next_zero_area_align(section->bitmap,
				section->total_cnt, 0, count, align);
	if (bit >= section->total_cnt)
		return NULL;

	bitmap_set(section->bitmap, bit, count);
	if ((1 == count) || (1 == align)) {
		section->bm_current = bit + count;
		ASSERT(section->bm_current < section->total_cnt);

		if (section->bm_current == section->total_cnt)
			section->bm_current = 0;
	}

	page = section->pages + bit;
	page->cnt = count;
	page->flags = (flags | PAGE_F_HEAD) & 0xffff;
	page->pfn = PAGE_ADDR(section->phy_base, bit) >> PAGE_SHIFT;

	/*
	 * update the block bitmap information.
	 */
	section->free_cnt -= count;
	if (section->block_section)
		alloc_pages_in_block(page, section);

	return page;
}

static struct page *alloc_pages_from_section(int pages, int align, int flags)
{
	struct page *page = NULL;
	struct mem_section *section;
	int i;

	flags &= PAGE_F_MASK;

	for (i = 0; i < nr_sections; i++) {
		section = &mem_sections[i];

		spin_lock(&section->lock);
		if (section->free_cnt < pages) {
			spin_unlock(&section->lock);
			continue;
		}

		page = __alloc_pages_from_section(section, pages, align, flags);
		spin_unlock(&section->lock);

		if (page)
			return page;
	}

	return NULL;
}

static void bzero_pages(struct page *page, int pages)
{
	memset((void *)page_va(page), 0, pages << PAGE_SHIFT);
}

struct page *__alloc_pages(int pages, int align, int flags)
{
	struct page *page;

	if ((pages <= 0) || (align == 0))
		return NULL;

	page = alloc_pages_from_section(pages, align, flags);
	if (!page) {
		pr_warn("no more pages\n");
		return NULL;
	}

	return page;
}

void *__get_free_pages(int pages, int align, int flags)
{
	struct page *page = NULL;

	page = __alloc_pages(pages, align, flags);
	if (page) {
		bzero_pages(page, pages);
		return (void *)page_va(page);
	}

	return NULL;
}

static struct page * get_page_in_section(struct mem_section *section, unsigned long addr)
{
	unsigned long start = (addr - section->vir_base) >> PAGE_SHIFT;

	return section->pages + start;
}

struct page *addr_to_page(unsigned long addr)
{
	struct mem_section *section;

	section = addr_to_mem_section((unsigned long)addr);
	if (!section) {
		pr_err("bad address 0x%lx\n", (unsigned long)addr);
		return NULL;
	}

	return get_page_in_section(section, addr);
}

static int free_pages_in_section(struct page *page, struct mem_section *ms)
{
	unsigned long flags = page_flags(page);
	unsigned long start, pstart;
	int count;

	/*
	 * if the page is not the page head or the page is used
	 * as slab or other, then it means its a slab memory
	 * or can not release by now
	 */
	ASSERT((flags != 0) && (flags & PAGE_F_HEAD) &&
			!(flags & PAGE_F_SLAB));
	/*
	 * clear all the pages in case the memory data leak.
	 */
	count = page_count(page);
	pstart = page_pa(page);
	ASSERT((pstart != 0) && (count != 0));

	start = (pstart - ms->phy_base) >> PAGE_SHIFT;
	bitmap_clear(ms->bitmap, start, count);
	ms->free_cnt += count;

	/*
	 * update the block information in this section if
	 * needed.
	 */
	if (ms->block_section)
		free_pages_in_block(page, ms);

	/*
	 * clear the page information last.
	 */
	memset(page, 0, sizeof(struct page));

	return 0;
}

int __free_pages(struct page *page)
{
	struct mem_section *section;

	section = addr_to_mem_section(page_va(page));
	if (!section) {
		pr_err("bad address to free 0x%lx\n", page_va(page));
		return -EFAULT;
	}

	spin_lock(&section->lock);
	free_pages_in_section(page, section);
	spin_unlock(&section->lock);

	return 0;
}

int free_pages(void *addr)
{
	struct mem_section *section;
	struct page *page;

	ASSERT(is_kva(addr));

	if (!IS_PAGE_ALIGN(addr))
		return -EINVAL;

	/*
	 * check whether this addr is in page section or
	 * block section or is just a slab memory
	 */
	section = addr_to_mem_section((unsigned long)addr);
	if (!section) {
		pr_warn("not page address 0x%lx\n", (unsigned long)addr);
		return -EFAULT;
	}

	spin_lock(&section->lock);

	/*
	 * if the page is not the page head or the page is used
	 * as slab or other, then it means its a slab memory
	 * or can not release by now
	 */
	page = get_page_in_section(section, (unsigned long)addr);
	if (page_flags(page) & PAGE_F_SLAB) {
		pr_warn("slab memory can not be freed by free_pages()\n");
		spin_unlock(&section->lock);
		return -EINVAL;
	}

	free_pages_in_section(page, section);
	spin_unlock(&section->lock);

	return 0;
}

static void *get_free_block_from_section(struct mem_section *ms, unsigned long flags)
{
	struct page *page;
	unsigned long start;
	unsigned long base;
	unsigned long *bitmap_addr;

	if (ms->free_block == 0)
		return NULL;

	start = find_next_zero_bit_loop(ms->block_bitmap,
			ms->current_block, ms->total_block);
	if (start >= ms->total_block)
		return NULL;

	/*
	 * mask the block bit in block bitmap.
	 */
	set_bit(start, ms->block_bitmap);

	ms->free_block--;
	ms->current_block = start + 1;
	if (ms->current_block == ms->total_block)
		ms->current_block = 0;

	flags |= PAGE_F_HEAD;
	page = ms->pages + (start * PAGES_PER_BLOCK);
	page->flags = (uint16_t)flags & 0xffff;
	page->cnt = PAGES_PER_BLOCK;
	base = ms->phy_base + (start << BLOCK_SHIFT);
	page->pfn = base >> PAGE_SHIFT;

	/*
	 * update page bitmap for this block in page bitmap.
	 * currently need make sure below limition:
	 * 1 - 64BIT OS, sizeof(unsigned long) = 8
	 * 2 - 2M huge page, 512 pages per block
	 * 3 - need 8 * unsigned long to store bitmap.
	 */
	start = BITS_TO_LONGS(start * PAGES_PER_BLOCK);
	bitmap_addr = ms->bitmap + start;
	bitmap_addr[0] = (unsigned long)-1;
	bitmap_addr[1] = (unsigned long)-1;
	bitmap_addr[2] = (unsigned long)-1;
	bitmap_addr[3] = (unsigned long)-1;
	bitmap_addr[4] = (unsigned long)-1;
	bitmap_addr[5] = (unsigned long)-1;
	bitmap_addr[6] = (unsigned long)-1;
	bitmap_addr[7] = (unsigned long)-1;

	return (void *)base;
}

void *get_free_block(unsigned long flags)
{
	struct mem_section *ms;
	void *base = 0;
	int i;

	flags &= PAGE_F_MASK; 
	flags |= PAGE_F_HUGE;

	for (i = 0; i < nr_sections; i++) {
		ms = &mem_sections[i];
		if (!ms->block_section)
			continue;

		spin_lock(&ms->lock);
		base = get_free_block_from_section(ms, flags);
		spin_unlock(&ms->lock);

		if (base)
			break;
	}

	return (void *)ptov(base);
}

void free_block(void *addr)
{
	free_pages(addr);
}
