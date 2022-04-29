#ifndef __MINOS_PAGE_H__
#define __MINOS_PAGE_H__

#include <minos/list.h>
#include <minos/memattr.h>
#include <minos/memory.h>

#define __GFP_KERNEL		0x00000001
#define __GFP_USER		0x00000002
#define __GFP_GUEST		0x00000004
#define __GFP_DMA		0x00000008
#define __GFP_SHARED		0x00000010
#define __GFP_SLAB		0x00000020
#define __GFP_HUGE		0x00000040
#define __GFP_IO		0x00000080

#define GFP_KERNEL		__GFP_KERNEL
#define GFP_USER		__GFP_USER
#define GFP_GUEST		__GFP_GUEST
#define GFP_DMA			__GFP_DMA
#define GFP_SLAB		__GFP_SLAB
#define GFP_SHARED		__GFP_SHARED
#define GFP_SHARED_IO		(__GFP_SHARED | __GFP_IO)
#define GFP_HUGE		(__GFP_USER | __GFP_HUGE)
#define GFP_HUGE_IO		(__GFP_USER | __GFP_HUGE | __GFP_IO)

struct page {
	uint16_t cnt;
	uint16_t flags;
	uint32_t pfn;		// this need make sure the physical range need smaller than 44BITs
	struct page *next;
} __packed;

#define page_count(page)	(page)->cnt
#define page_pa(page)		((page)->pfn << PAGE_SHIFT)
#define page_va(page)		ptov(page_pa(page))
#define page_flags(page)	(page)->flags

int free_pages(void *addr);
struct page *addr_to_page(unsigned long addr);
void *__get_free_pages(int pages, int align, int flags);
void *get_free_block(unsigned long flags);
void free_block(void *addr);
void page_init(void);
void *get_io_pages(int pages);
void free_io_pages(void *addr);

int __free_pages(struct page *page);
struct page *__alloc_pages(int pages, int align, int flags);

static inline struct page *alloc_pages(int pages, int flags)
{
	return __alloc_pages(pages, 1, flags);
}

static inline void *get_free_page(int flags)
{
	return __get_free_pages(1, 1, flags);
}

static inline void *get_free_pages(int pages, int flags)
{
//	if (flags & __VM_IO)
//		return get_io_pages(pages);
//	else
		return __get_free_pages(pages, 1, flags);
}

#define get_static_pages(pages)	alloc_kpages(pages)

#endif
