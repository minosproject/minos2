/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
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
#include <minos/kobject.h>
#include <minos/uaccess.h>
#include <minos/mm.h>
#include <minos/sched.h>
#include <minos/vspace.h>

struct pma_mapping_entry {
	unsigned long base;
	struct list_head list;
	struct process *proc;
};

/*
 * create_pma();
 * map_pma(-1, handle, unsigned long base, unsigned long end). // map to self
 * read_data();
 * map_pma(process_handle, handle, unsigned long base, unsigned end); // map to target
 * destroy_pma();
 */
struct pma {
	unsigned long vm_flags;
	struct list_head mapping;
	struct kobject kobj;
	int type;

	/*
	 * if the PMA is shared, the memory region will mapped
	 * to the shared memory region of the process. if the
	 * PMA is privated and created by the root service to
	 * map the elf or other section of a process
	 *
	 * when the PMA can be shared by other process, it will
	 * allocated consecutive memory region, so the normal process
	 * can map it to its shared memory region, since the normal
	 * memory region can not get its virtual address information.
	 */
	unsigned long pstart;
	unsigned long pend;

	struct page *page_list;
	unsigned long psize;

	pid_t owner;
	spinlock_t lock;
};

static void free_pma_memory(struct pma *p)
{
	struct page *page = p->page_list, *tmp;

	BUG_ON((p->pstart != 0) && (p->page_list != NULL));

	if (p->vm_flags & __VM_PFNMAP)
		return;

	if (p->pstart) {
		free_pages((void *)pa2va(p->pstart));
		return;
	}

	do {
		tmp = page->next;
		__free_pages(page);
		page = tmp;
	} while (page != NULL);
}

static void *pma_map(struct kobject *kobj, struct process *proc, unsigned long virt)
{
	struct pma *p = (struct pma *)kobj->data;
	struct page *page = p->page_list;
	unsigned long start = virt;
	unsigned long size = p->psize;
	struct pma_mapping_entry *pme;
	int ret;

	pme = zalloc(sizeof(struct pma_mapping_entry));
	if (!pme)
		return ERROR_PTR(ENOMEM);

	if (p->pstart) {
		/*
		 * the PMA region will map to the shared memory of the
		 * process.
		 */
		pme->base = start = pa2sva(p->pstart);
		ret = map_process_memory(proc, start, p->psize, p->pstart, p->vm_flags);
		if (ret) {
			free(pme);
			return ERROR_PTR(ret);
		}
	} else {
		pme->base = start = virt;
		if (!IS_PAGE_ALIGN(virt))
			return ERROR_PTR(EINVAL);

		do {
			ret = map_process_memory(proc, start,
					PAGE_SIZE, page_pa(page), p->vm_flags);
			if (ret) {
				free(pme);
				return ERROR_PTR(ENOMEM);
			}

			page = page->next;
			start += PAGE_SIZE;
			size -= PAGE_SIZE;
		} while (size > 0);
	}

	/*
	 * allocate a mapping entry to record the mapping info.
	 */
	pme->proc = proc;
	spin_lock(&p->lock);
	list_add_tail(&p->mapping, &pme->list);
	spin_unlock(&p->lock);

	return (void *)pme->base;
}

static int pma_unmap(struct kobject *kobj, struct process *proc)
{
	struct pma *p = (struct pma *)kobj->data;
	struct pma_mapping_entry *pme, *tmp, *out = NULL;

	spin_lock(&p->lock);
	list_for_each_entry_safe(pme, tmp, &p->mapping, list) {
		if (pme->proc == proc) {
			out = pme;
			list_del(&pme->list);
			break;
		}
	}
	spin_unlock(&p->lock);
	if (!out)
		return -ENOENT;

	return unmap_process_memory(proc, out->base, p->psize);
}

static void *pma_mmap(struct kobject *kobj, right_t right)
{
	return pma_map(kobj, current_proc, 0);
}

static int pma_munmap(struct kobject *kobj, right_t right)
{
	return pma_unmap(kobj, current_proc);
}

int sys_map(handle_t proc_handle, handle_t pma_handle,
		unsigned long virt, size_t size, right_t right)
{
	struct kobject *kobj_proc;
	struct kobject *kobj_pma;
	right_t right_proc, right_pma;
	int ret = -EACCES;
	void *addr;

	if (WRONG_HANDLE(proc_handle) || WRONG_HANDLE(pma_handle))
		return -ENOENT;

	if (current_proc->kobj.right != KOBJ_RIGHT_ROOT)
		return -EPERM;

	ret = get_kobject(proc_handle, &kobj_proc, &right_proc);
	if (ret)
		return -ENOENT;
	ret = get_kobject(pma_handle, &kobj_pma, &right_pma);
	if (ret) {
		put_kobject(kobj_proc);
		return -ENOENT;
	}

	if ((kobj_proc->type != KOBJ_TYPE_PROCESS) ||
			(kobj_pma->type != KOBJ_TYPE_PMA)) {
		ret = -EBADF;
		goto out;
	}

	addr = pma_map(kobj_pma, (struct process *)kobj_proc->data, virt);
	if (IS_ERROR_PTR(addr))
		ret = (int)(unsigned long)addr;

out:
	put_kobject(kobj_proc);
	put_kobject(kobj_pma);

	return ret;
}

int sys_unmap(handle_t proc_handle, handle_t pma_handle)
{
	struct kobject *kobj_proc;
	struct kobject *kobj_pma;
	right_t right_proc, right_pma;
	int ret;

	if (current_proc->kobj.right != KOBJ_RIGHT_ROOT)
		return -EPERM;

	if (WRONG_HANDLE(proc_handle) || WRONG_HANDLE(pma_handle))
		return -ENOENT;

	ret = get_kobject(proc_handle, &kobj_proc, &right_proc);
	if (ret)
		return -ENOENT;
	ret = get_kobject(pma_handle, &kobj_pma, &right_pma);
	if (ret) {
		put_kobject(kobj_proc);
		return -ENOENT;
	}

	if ((kobj_proc->type != KOBJ_TYPE_PROCESS) ||
			(kobj_pma->type != KOBJ_TYPE_PMA)) {
		ret = -EBADF;
		goto out;
	}

	ret = pma_unmap(kobj_pma, (struct process *)kobj_proc->data);

out:
	put_kobject(kobj_proc);
	put_kobject(kobj_pma);

	return ret;
}

static void pma_release(struct kobject *kobj)
{
	struct pma *p = (struct pma *)kobj->data;

	if (p->type != PMA_TYPE_MMIO) {
		if (p->vm_flags & __VM_IO)
			free_io_pages((void *)pa2va(p->pstart));
		else
			free_pages((void *)pa2va(p->pstart));
	}

	free(p);
}

static void free_pma_pages(struct page *head)
{
	struct page *tmp = head;
	struct page *next;

	while (tmp) {
		next = tmp->next;
		__free_pages(tmp);
		tmp = next;
	}
}

static int pma_add_pages(struct kobject *kobj, int pages)
{
	struct pma *p = (struct pma *)kobj->data;
	struct page *page;
	struct page *head = NULL;
	struct page *tail = NULL;
	int i;

	if (pages <= 0)
		return -EINVAL;
	if (kobj->right & KOBJ_RIGHT_SHARED)
		return -EPERM;

	for (i = 0; i < pages; i++) {
		page = alloc_pages(1, GFP_USER);
		if (!page) {
			free_pma_pages(head);
			return -ENOMEM;
		}

		page->next = head;
		head = page;

		if (tail == NULL)
			tail = page;
	}

	/*
	 * insert the new pages to the pma
	 */
	spin_lock(&p->lock);
	tail->next = p->page_list;
	p->page_list = head;
	p->psize += pages << PAGE_SHIFT;
	spin_unlock(&p->lock);

	return 0;
}

static long pma_ctl(struct kobject *kobj, int req, unsigned long data)
{
	int ret;

	switch (req) {
	case KOBJ_PMA_ADD_PAGES:
		ret = pma_add_pages(kobj, (int)data);
		break;
	default:
		ret = -ENOSYS;
		pr_err("unknow action 0x%x for pma kobject\n", req);
		break;
	}

	return ret;
}

static struct kobject_ops pma_ops = {
	.mmap		= pma_mmap,
	.munmap		= pma_munmap,
	.ctl		= pma_ctl,
	.release	= pma_release,
};

static inline unsigned long pma_flags(int type, right_t right)
{
	unsigned long flags;

	switch (right & KOBJ_RIGHT_RWX) {
	case KOBJ_RIGHT_RW:
		flags = VM_RW;
		break;
	case KOBJ_RIGHT_RWX:
		flags = VM_RWX;
		break;
	default:
		flags = VM_RO;
		break;
	}

	if (type == PMA_TYPE_DMA)
		flags |= __VM_IO;
	else if (type == PMA_TYPE_MMIO)
		flags |= __VM_PFNMAP | __VM_IO;

	flags |= VM_PMA;

	return flags;
}

static int allocate_pma_memory(struct pma *p, int cnt,
		right_t right, int type)
{
	struct page *page;
	int i;

	/*
	 * if this PMA need to shared among in different process
	 * allocate a continuously memory region.
	 */
	if ((right & KOBJ_RIGHT_SHARED) || (type == PMA_TYPE_DMA)) {
		p->pstart = va2pa(get_free_pages(cnt, GFP_USER));
		if (!p->pstart)
			return -ENOMEM;

		p->psize = cnt << PAGE_SHIFT;
		p->pend = p->pstart + p->pend;
		return 0;
	}

	for (i = 0; i < cnt; i++) {
		page = alloc_pages(1, GFP_USER);
		if (!page) {
			free_pma_memory(p);
			return -ENOMEM;
		}

		page->next = p->page_list;
		p->page_list = page;
	}

	return 0;
}

static struct kobject *pma_create(right_t right,
		right_t right_req, unsigned long data)
{
	struct pma_create_arg args;
	int ret;
	struct pma *p;

	ret = copy_from_user(&args, (void __user *)data, sizeof(struct pma_create_arg));
	if (ret <= 0)
		return ERROR_PTR(EFAULT);

	if (args.type >= PMA_TYPE_MAX)
		return ERROR_PTR(EINVAL);

	/*
	 * only root service or who have the right to create
	 * MMIO memory can do this.
	 */
	if (!(current_proc->kobj.right & KOBJ_RIGHT_ROOT) &&
			(args.type == PMA_TYPE_MMIO))
		return ERROR_PTR(EPERM);

	if ((args.type == PMA_TYPE_MMIO) &&
			((args.start == 0) || (args.end == 0)))
		return ERROR_PTR(EINVAL);

	if (args.end < args.start)
		return ERROR_PTR(EINVAL);

	/*
	 * data will be the page count of the request memory size
	 */
	p = zalloc(sizeof(struct pma));
	if (!p)
		return ERROR_PTR(ENOMEM);

	p->vm_flags = pma_flags(args.type, right);
	if (args.type == PMA_TYPE_MMIO) {
		p->pstart = args.start;
		p->pend = args.end;
		p->psize = p->pend - p->pstart;
	} else {
		if (args.cnt > 0) {
			p->psize = args.cnt << PAGE_SHIFT;
			ret = allocate_pma_memory(p, args.cnt, right_req, args.type);
			if (ret) {
				free(p);
				return ERROR_PTR(ENOMEM);
			}
		}
	}

	p->type = args.type;
	init_list(&p->mapping);
	spin_lock_init(&p->lock);
	p->owner = current_pid;
	p->kobj.ops = &pma_ops;
	kobject_init(&p->kobj, KOBJ_TYPE_PMA, right, (unsigned long)p);

	return &p->kobj;
}
DEFINE_KOBJECT(endpoint, KOBJ_TYPE_PMA, pma_create);
