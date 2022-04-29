#ifndef _MINOS_MM_H_
#define _MINOS_MM_H_

#include <minos/list.h>
#include <minos/spinlock.h>
#include <minos/memattr.h>
#include <minos/memory.h>
#include <minos/page.h>
#include <minos/slab.h>

struct vspace;

struct mm_notifier_ops {
	void (*unmap_range)(struct vspace *vspace, unsigned long start,
			unsigned long end, int flags);
};

struct vspace {
	pgd_t *pgdp;
	spinlock_t lock;
	uint16_t asid;

	/*
	 * indicate that the vspace is used in kernel, means
	 * kernel is acess the userspace pagees, so do not release
	 * the pages if unmap to avoid kernel hang or data breach.
	 */
	atomic_t inuse;
	struct page *release_pages;
	struct mm_notifier_ops *notifier_ops;
	void *pdata;
};

void release_vspace_pages(struct vspace *vs);

int create_host_mapping(unsigned long vir, unsigned long phy,
		size_t size, unsigned long flags);

int destroy_host_mapping(unsigned long vir, size_t size);

int change_host_mapping(unsigned long vir, unsigned long phy,
		unsigned long new_flags);

void *io_remap(virt_addr_t vir, size_t size);

int io_unmap(virt_addr_t vir, size_t size);

#endif
