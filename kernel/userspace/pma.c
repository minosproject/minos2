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
#include <minos/mm.h>
#include <minos/sched.h>
#include <uspace/vspace.h>
#include <uspace/kobject.h>
#include <uspace/uaccess.h>
#include <uspace/proc.h>

#define PMA_RIGHT	(KOBJ_RIGHT_CTL | KOBJ_RIGHT_MMAP | KOBJ_RIGHT_RWX)
#define PMA_RIGHT_MASK	(KOBJ_RIGHT_CTL | KOBJ_RIGHT_MMAP | KOBJ_RIGHT_RWX)

struct pma_mapping_entry {
	unsigned long virt;
	size_t size;
	struct list_head list;
	struct process *mapper;		// who exected this action.
	struct process *proc;		// mapped at where.
};

/*
 * create_pma();
 * map_pma(-1, handle, unsigned long base, unsigned long end). // map to self
 * read_data();
 * map_pma(process_handle, handle, unsigned long base, unsigned end); // map to target
 * destroy_pma();
 */
struct pma {
	unsigned long vmflags;
	struct kobject kobj;
	struct list_head head;
	spinlock_t lock;
	uint8_t type;
	uint8_t consequent;

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
	unsigned long psize;
	struct page *page_list;
};

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

static void free_pma_memory(struct pma *p)
{
	BUG_ON((p->pstart != 0) && (p->page_list != NULL));

	if (p->vmflags & __VM_PFNMAP)
		return;

	if (p->pstart) {
		if (p->type == PMA_TYPE_KCACHE)
			free_pages((void *)p->pstart);
		else
			free_pages((void *)pa2va(p->pstart));
	} else {
		free_pma_pages(p->page_list);
	}
}

static int pma_mmap(struct kobject *kobj, right_t right,
		void **addr, unsigned long *msize)
{
	struct pma *p = (struct pma *)kobj->data;
	unsigned long vstart, pstart, size;

	if (!p->pstart)
		return -EPERM;

	/*
	 * TBD
	 */
	vstart = PAGE_ALIGN(pa2sva(p->pstart));
	pstart = PAGE_ALIGN(p->pstart);
	size = PAGE_BALIGN(p->pstart + p->psize) - pstart;

	if (map_process_memory(current_proc, vstart, size, pstart, p->vmflags))
		return -EFAULT;

	*addr = (void *)pa2sva(p->pstart);
	*msize = p->psize;

	return 0;
}

static int pma_munmap(struct kobject *kobj, right_t right)
{
	struct pma *p = (struct pma *)kobj->data;
	unsigned long vstart, size;

	if (!p->pstart)
		return -EPERM;

	vstart = PAGE_ALIGN(pa2sva(p->pstart));
	size = PAGE_BALIGN(vstart + p->psize) - vstart;

	return unmap_process_memory(current_proc, vstart, size);
}

static int pma_close(struct kobject *kobj, right_t right,
		struct process *proc)
{
	struct pma *p = (struct pma *)kobj->data;
	struct pma_mapping_entry *pme, *tmp;
	int ret;

	spin_lock(&p->lock);
	list_for_each_entry_safe(pme, tmp, &p->head, list) {
		if (pme->mapper != proc)
			continue;

		list_del(&pme->list);
		ret = unmap_process_memory(pme->proc, pme->virt, pme->size);
		free(pme);
		WARN_ON(ret, "unmap pma in %d failed\n", proc->pid);
	}
	spin_unlock(&p->lock);

	if (!p->pstart)
		return 0;
	else
		return unmap_process_memory(proc, pa2sva(p->pstart), p->psize);
}

static void *__sys_pma_map(struct pma *p, struct process *proc,
		unsigned long virt, size_t size)
{
	struct page *page = p->page_list;
	unsigned long start = virt;
	struct pma_mapping_entry *pme;
	int ret;

	size = (size > p->psize) ? p->psize : size;
	pme = zalloc(sizeof(struct pma_mapping_entry));
	if (!pme)
		return ERROR_PTR(-ENOMEM);
	pme->virt = virt;
	pme->size = size;
	pme->mapper = current_proc;
	pme->proc = proc;

	if (p->pstart) {
		ret = map_process_memory(proc, start,
				size, p->pstart, p->vmflags);
	} else {
		do {
			ret = map_process_memory(proc, start,
					PAGE_SIZE,page_pa(page), p->vmflags);
			if (ret)
				break;
			page = page->next;
			start += PAGE_SIZE;
			size -= PAGE_SIZE;
		} while (size > 0);
	}

	if (ret) {
		free(pme);
		unmap_process_memory(proc, virt, size);
		return ERROR_PTR(ret);
	}

	/*
	 * allocate a mapping entry to record the mapping info.
	 * pme->proc is set to the process who map this memory
	 * sice only root service will call sys_map.
	 */
	spin_lock(&p->lock);
	list_add_tail(&p->head, &pme->list);
	spin_unlock(&p->lock);

	return (void *)pme->virt;
}

static int __sys_pma_unmap(struct pma *p, struct process *proc,
		unsigned long virt, size_t size)
{
	struct pma_mapping_entry *entry, *tmp, *out = NULL;

	spin_lock(&p->lock);
	list_for_each_entry_safe(entry, tmp, &p->head, list) {
		if ((entry->mapper == current_proc) &&
				(entry->proc == proc) &&
				(entry->virt == virt) &&
				(entry->size == size)) {
			list_del(&entry->list);
			out = entry;
			break;
		}
	}
	spin_unlock(&p->lock);

	if (!out)
		return -ENOENT;

	unmap_process_memory(proc, virt, size);
	free(out);

	return 0;
}

static int sys_handle_pma(handle_t proc_handle, handle_t pma_handle,
		unsigned long virt, size_t size, right_t right, int map)
{
	right_t right_proc, right_pma;
	struct kobject *kobj_proc = NULL;
	struct kobject *kobj_pma = NULL;
	struct process *proc;
	int ret = -EACCES;
	void *addr;

	/*
	 * only the root service can map a pma to other process's
	 * vspace.
	 */
	if (proc_handle != -1) {
		if (!proc_is_root(current_proc))
			return -EPERM;

		ret = get_kobject(proc_handle, &kobj_proc, &right_proc);
		if (ret)
			return -ENOENT;

		if (kobj_proc->type != KOBJ_TYPE_PROCESS) {
			kobject_put(kobj_proc);
			return -EBADF;
		}
		proc = (struct process *)kobj_proc->data;
	} else {
		proc = current_proc;
	}

	ret = get_kobject(pma_handle, &kobj_pma, &right_pma);
	if (ret) {
		ret = -ENOENT;
		goto out_pma_kobj;
	}

	if (kobj_pma->type != KOBJ_TYPE_PMA) {
		ret = -EBADF;
		goto out;
	}

	if (map) {
		addr = __sys_pma_map((struct pma *)kobj_pma->data, proc,
				virt, size);
		if (IS_ERROR_PTR(addr))
			ret = (int)(unsigned long)addr;
	} else {
		ret = __sys_pma_unmap((struct pma *)kobj_pma->data, proc,
				virt, size);
	}

out:
	put_kobject(kobj_pma);
out_pma_kobj:
	if (kobj_proc)
		put_kobject(kobj_proc);

	return ret;
}

int sys_map_pma(handle_t proc_handle, handle_t pma_handle,
		unsigned long virt, size_t size, right_t right)
{
	return sys_handle_pma(proc_handle, pma_handle, virt, size, right, 1);
}

int sys_unmap_pma(handle_t proc_handle, handle_t pma_handle,
		unsigned long virt, size_t size)
{
	return sys_handle_pma(proc_handle, pma_handle, virt, size, 0, 0);
}

static void pma_release(struct kobject *kobj)
{
	struct pma *p = (struct pma *)kobj->data;

	if (!is_list_empty(&p->head)) {
		pr_err("pma busy memleak error!\n");
		return;
	}

	free_pma_memory(p);
	free(p);
}

static int pma_add_pages(struct kobject *kobj, int pages)
{
	struct pma *p = (struct pma *)kobj->data;
	struct page *page;
	struct page *head = NULL;
	struct page *tail = NULL;
	int i;

	if ((pages <= 0) || (p->type != PMA_TYPE_NORMAL))
		return -EINVAL;

	if (p->consequent)
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

static long pma_get_size(struct kobject *kobj)
{
	struct pma *p = (struct pma *)kobj->data;

	return p->psize;
}

static long pma_ctl(struct kobject *kobj, int req, unsigned long data)
{
	int ret;

	switch (req) {
	case KOBJ_PMA_ADD_PAGES:
		ret = pma_add_pages(kobj, (int)data);
		break;
	case KOBJ_PMA_GET_SIZE:
		return pma_get_size(kobj);
	default:
		ret = -ENOSYS;
		pr_err("unknow action 0x%x for pma kobject\n", req);
		break;
	}

	return ret;
}

static long pma_write(struct kobject *kobj, void __user *data, size_t data_size,
		void __user *extra, size_t extra_size, uint32_t timeout)
{
	struct pma *p = (struct pma *)kobj->data;

	if (p->type != PMA_TYPE_KCACHE)
		return -EPERM;

	if (data_size > p->psize)
		return -EINVAL;

	return copy_from_user((void *)p->pstart, data, data_size);
}

static long pma_read(struct kobject *kobj, void __user *data, size_t data_size,
		size_t *actual_data, void __user *extra, size_t extra_size,
		size_t *actual_extra, uint32_t timeout)
{
	struct pma *p = (struct pma *)kobj->data;

	if (p->type != PMA_TYPE_KCACHE)
		return -EPERM;

	if (data_size > p->psize)
		return -EINVAL;

	return copy_to_user(data, (void *)p->pstart, data_size);
}

static struct kobject_ops pma_ops = {
	.mmap		= pma_mmap,
	.munmap		= pma_munmap,
	.send		= pma_write,
	.recv		= pma_read,
	.ctl		= pma_ctl,
	.release	= pma_release,
	.close		= pma_close,
};

static inline unsigned long pma_flags(int type, right_t right)
{
	unsigned long flags = 0;

	if (right & KOBJ_RIGHT_READ)
		flags |= __VM_READ;
	if (right & KOBJ_RIGHT_WRITE)
		flags |= __VM_WRITE;
	if (right & KOBJ_RIGHT_EXEC)
		flags |= __VM_EXEC;

	WARN_ON(flags == 0, "request pma with no access right\n");

	if (type == PMA_TYPE_DMA)
		flags |= __VM_IO;
	else if (type == PMA_TYPE_MMIO)
		flags |= __VM_PFNMAP | __VM_IO;
	else if (type == PMA_TYPE_PMEM)
		flags |= __VM_PFNMAP;

	flags |= VM_PMA;

	return flags;
}

static int allocate_pma_memory(struct pma *p, size_t size, int type)
{
	size_t cnt = size >> PAGE_SHIFT;
	struct page *page;
	int i;

	/*
	 * if this PMA need to shared among in different process
	 * allocate a continuously memory region.
	 */
	if (p->consequent || (type == PMA_TYPE_DMA)) {
		p->pstart = va2pa(get_free_pages(cnt, GFP_USER));
		if (!p->pstart)
			return -ENOMEM;

		p->psize = cnt << PAGE_SHIFT;
		p->pend = p->pstart + p->psize;
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

static int __create_new_pma(struct kobject **kobj,
		right_t *right, struct pma_create_arg *args)
{
	right_t right_mask = PMA_RIGHT_MASK;
	right_t right_ret = PMA_RIGHT;
	int fixup_pmem = 0;
	struct pma *p;
	int ret;

	if ((args->type == PMA_TYPE_MMIO) || (args->type == PMA_TYPE_PMEM)) {
		if (args->size == 0)
			return -EINVAL;
		fixup_pmem = 1;
	}

	/*
	 * data will be the page count of the request memory size
	 */
	p = zalloc(sizeof(struct pma));
	if (!p)
		return -ENOMEM;

	p->vmflags = pma_flags(args->type, args->right);
	if (fixup_pmem) {
		p->pstart = args->start;
		p->pend = args->start + args->size;
		p->psize = args->size;
		p->consequent = 1;
	} else if (args->type == PMA_TYPE_KCACHE) {
		p->pstart = (unsigned long)get_free_page(GFP_KERNEL);
		if (p->pstart == 0) {
			free(p);
			return -ENOMEM;
		}
		p->pend = p->pstart + PAGE_SIZE;
		p->psize = PAGE_SIZE;
		right_mask &= ~KOBJ_RIGHT_MMAP;
		right_ret &= ~KOBJ_RIGHT_MMAP;
		p->consequent = 1;
	} else {
		p->consequent = !!args->consequent;
		if (args->size > 0) {
			p->psize = args->size;
			ret = allocate_pma_memory(p, args->size, args->type);
			if (ret) {
				free(p);
				return -ENOMEM;
			}
		}

		/*
		 * if the PMA is not consequented, it can not be called
		 * kobject_mmap()
		 */
		if (!p->consequent) {
			right_mask &= ~KOBJ_RIGHT_MMAP;
			right_ret &= ~KOBJ_RIGHT_MMAP;
		}
	}

	p->type = args->type;
	init_list(&p->head);
	spin_lock_init(&p->lock);
	p->kobj.ops = &pma_ops;
	kobject_init(&p->kobj, KOBJ_TYPE_PMA, right_mask, (unsigned long)p);
	*kobj = &p->kobj;
	*right = right_ret;

	return 0;
}

int create_new_pma(struct kobject **kobj, right_t *right, struct pma_create_arg *args)
{
	return __create_new_pma(kobj, right, args);
}

static int pma_create(struct kobject **kobj, right_t *right, unsigned long data)
{
	struct pma_create_arg args;
	int ret;

	ret = copy_from_user(&args, (void __user *)data, sizeof(struct pma_create_arg));
	if (ret <= 0)
		return ret;

	if (args.type >= PMA_TYPE_MAX)
		return -EINVAL;

	switch (args.type) {
	case PMA_TYPE_DMA:
	case PMA_TYPE_MMIO:
	case PMA_TYPE_PMEM:
		if (!proc_can_vmctl(current_proc))
			return -EPERM;
		break;
	case PMA_TYPE_KCACHE:
		if (args.size > PAGE_SIZE)
			return -E2BIG;
		break;
	case PMA_TYPE_NORMAL:
		if (!proc_is_root(current_proc) && (args.size > HUGE_PAGE_SIZE))
			return -E2BIG;
		break;
	default:
		break;
	}

	return __create_new_pma(kobj, right, &args);
}
DEFINE_KOBJECT(pma, KOBJ_TYPE_PMA, pma_create);
