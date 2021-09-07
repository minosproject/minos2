/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <minos/debug.h>
#include <minos/list.h>
#include <minos/kobject.h>
#include <minos/map.h>
#include <minos/kmalloc.h>

#include <pangu/proc.h>

#define vma_init(vma, _base, _end)	\
	do {				\
		vma->pma_handle = -1;	\
		vma->start = _base;	\
		vma->end = _end;	\
	} while (0)

static void __release_vma(struct process *proc, struct vma *vma)
{
	struct vma *cur, *tmp;

	vma->pma_handle = -1;
	vma->anon = 0;

	if (vma->list.next != NULL) {
		pr_err("vma is not is in use\n");
		return;
	}

	/*
	 * try to merge the vma to a bigger one
	 */
repeat:
	list_for_each_entry_safe(cur, tmp, &proc->vma_free, list) {
		if (cur->start == vma->end) {
			list_del(&cur->list);
			vma->end = cur->end;
			kfree(cur);
			goto repeat;
		}

		if (vma->start == cur->end) {
			list_del(&cur->list);
			vma->start = cur->start;
			kfree(cur);
			goto repeat;
		}
	}

	list_add(&proc->vma_free, &vma->list);
}

void release_vma(struct process *proc, struct vma *vma)
{

	if (vma->list.next != NULL)
		list_del(&vma->list);

	return __release_vma(proc, vma);
}

static struct vma *split_vma(struct process *proc, struct vma *vma,
		unsigned long base, unsigned long end)
{
	size_t left_size, right_size;
	struct vma *left, *right;

	left_size = base - vma->start;
	right_size = vma->end - end;

	if ((left_size == 0) && (right_size == 0))
		return vma;

	if (left_size > 0) {
		left = kzalloc(sizeof(struct vma));
		if (!left)
			goto out_err;
		vma_init(left, vma->start, base);
		list_add(&proc->vma_free, &left->list);
	}

	if (right_size > 0) {
		right = kzalloc(sizeof(struct vma));
		if (!right)
			goto out_err_right;
		vma_init(right, end, vma->end);
		list_add(&proc->vma_free, &right->list);
	}

	vma->start = base;
	vma->end = end;

	return vma;

out_err_right:
	list_del(&left->list);
	kfree(left);
out_err:
	list_add(&proc->vma_free, &vma->list);
	return NULL;
}

struct vma *__request_vma(struct process *proc, unsigned long base,
		size_t size, unsigned int perm, int anon)
{
	unsigned long new_base = base, new_end = base + size;
	struct vma *vma, *old, *out = NULL;

	if ((base != 0) && (!IS_PAGE_ALIGN(base))) {
		pr_err("%s invalid request address 0x%lx\n", __func__, base);
		return NULL;
	}

	list_for_each_entry_safe(vma, old, &proc->vma_free, list) {
		if (base == 0) {
			new_base = vma->start;
			new_end = vma->start + size;
		}

		if ((new_base >= vma->start) && (new_end <= vma->end)) {
			out = vma;
			break;
		}
	}

	if (!out) return NULL;

	list_del(&vma->list);
	out = split_vma(proc, out, new_base, new_end);
	if (out) {
		out->perm = perm;
		out->anon = anon;
		list_add_tail(&proc->vma_used, &out->list);
	}

	return out;
}

int create_pma(struct process *proc, int type, int right,
		int right_req, unsigned long base, size_t size)
{
	struct pma_create_arg args = {
		.cnt = size >> PAGE_SHIFT,
		.type = type,
		.start = base,
		.end = base + size,
	};

	return kobject_create(KOBJ_TYPE_PMA, right,
			right_req, (unsigned long)&args);
}

struct vma *request_vma(struct process *proc, unsigned long base,
		size_t size, unsigned int perm, int anon)
{
	struct vma *vma;
	int ret;
	
	vma = __request_vma(proc, base, size, perm, anon);
	if (!vma)
		return NULL;

	/*
	 * if this is anon mapping vma area, return directly.
	 * else allocate a pma for this mapping to share with
	 * other process or orther usage.
	 */
	if (anon)
		return vma;

	vma->pma_handle = create_pma(proc, PMA_TYPE_NORMAL, perm, perm, 0, size);
	if (vma->pma_handle < 0) {
		release_vma(proc, vma);
		return NULL;
	}

	ret = sys_map(proc->proc_handle, vma->pma_handle, base, size, perm);
	if (ret) {
		kobject_close(vma->pma_handle);
		release_vma(proc, vma);
		return NULL;
	}

	return vma;
}

struct vma *find_vma(struct process *proc, unsigned long base)
{
	struct vma *vma;

	list_for_each_entry(vma, &proc->vma_used, list) {
		if (vma->start == base)
			return vma;
	}

	return NULL;
}

void vspace_init(struct process *proc)
{
	struct vma *vma;

	init_list(&proc->vma_free);
	init_list(&proc->vma_used);

	vma = kzalloc(sizeof(struct vma));
	if (!vma) {
		pr_err("vma init fail for proc\n");
		return;
	}

	vma->start = PROCESS_ADDR_BOTTOM;
	vma->end = PROCESS_ADDR_TOP;		// bottom 256G
	list_add(&proc->vma_free, &vma->list);
}
