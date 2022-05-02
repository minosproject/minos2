/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <errno.h>

#include <minos/debug.h>
#include <minos/list.h>
#include <minos/kobject.h>
#include <minos/proto.h>

#include <pangu/kmalloc.h>
#include <pangu/proc.h>
#include <pangu/mm.h>

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

int create_pma(int type, int right, unsigned long base, size_t size)
{
	struct pma_create_arg args = {
		.size = size,
		.type = type,
		.start = base,
		.right = right,
	};

	return kobject_create(KOBJ_TYPE_PMA, (unsigned long)&args);
}

struct vma *request_vma(struct process *proc, int pma_handle,
			unsigned long base, size_t size,
			unsigned int perm, int anon)
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
	if (anon && pma_handle <= 0)
		return vma;

	if (pma_handle <= 0) {
		vma->pma_handle = create_pma(PMA_TYPE_NORMAL, perm, 0, size);
		if (vma->pma_handle < 0) {
			release_vma(proc, vma);
			return NULL;
		}
	} else {
		vma->pma_handle = pma_handle;
	}

	ret = sys_map(proc->proc_handle, vma->pma_handle, base, size, perm);
	if (ret) {
		if (pma_handle <= 0)
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
		if ((base >= vma->start) && (base < vma->end))
			return vma;
	}

	return NULL;
}

int unmap_self_memory(void *base)
{
	struct vma *vma;
	int ret;

	if (!IS_PAGE_ALIGN((unsigned long)base)) {
		pr_err("%s address %p is not page align\n", __func__, base);
		return -EINVAL;
	}

	vma = find_vma(self, (unsigned long)base);
	if (!vma)
		return -ENOENT;

	if (vma->pma_handle <= 0) {
		pr_err("%s invalid pma handle\n", __func__);
		return -EINVAL;
	}

	ret = sys_unmap(self->proc_handle, vma->pma_handle,
			vma->start, vma->end - vma->start);
	if (ret)
		return ret;

	release_vma(self, vma);

	return 0;
}

void *map_self_memory(int pma_handle, size_t size, int perm)
{
	struct vma *vma;
	int ret;

	if (pma_handle <= 0) {
		pr_err("%s bad pma handle %d\n", __func__, pma_handle);
		return NULL;
	}

	vma = __request_vma(self, 0, size, perm, 0);
	if (!vma)
		return NULL;
	vma->pma_handle = pma_handle;

	/*
	 * map can only be called by root service, to control
	 * the mapping of a process.
	 */
	ret = sys_map(self->proc_handle, pma_handle, vma->start, size, perm);
	if (ret) {
		release_vma(self, vma);
		return NULL;
	}

	return (void *)vma->start;
}

long pangu_mmap(struct process *proc, struct proto *proto, void *data)
{
	size_t len = proto->mmap.len;
	int prot = proto->mmap.prot;
	struct vma *vma;
	int perm = 0;
	void *addr = (void *)-1;

	if ((proto->mmap.addr != NULL) || (proto->mmap.fd != -1)) {
		pr_err("only support map anon mapping for process\n");
		goto out;
	}

	if (prot & PROT_EXEC)
		perm |= KOBJ_RIGHT_EXEC;
	if (prot & PROT_WRITE)
		perm |= KOBJ_RIGHT_WRITE;
	if (prot & PROT_READ)
		perm |= KOBJ_RIGHT_READ;

	len = BALIGN(len, PAGE_SIZE);
	vma = request_vma(proc, 0, 0, len, perm, 1);
	if (vma)
		addr = (void *)vma->start;
out:
	kobject_reply_errcode(proc->proc_handle, proto->token, (long)addr);

	return 0;
}

static unsigned long __pangu_brk(struct process *proc, struct proto *proto, void *data)
{
	unsigned long addr = (unsigned long)proto->brk.addr;

	if (addr == 0)
		return (long)proc->brk_cur;
	if ((addr < proc->brk_start) || (addr >= proc->brk_end))
		return -1;
	proc->brk_cur = addr;

	return addr;
}

long pangu_brk(struct process *proc, struct proto *proto, void *data)
{
	unsigned long addr = __pangu_brk(proc, proto, data);
	kobject_reply_errcode(proc->proc_handle, proto->token, addr);
	return 0;
}

long pangu_mprotect(struct process *proc, struct proto *proto, void *data)
{
	unsigned long end = (unsigned long)proto->mprotect.addr + proto->mprotect.len;
	struct vma *vma = find_vma(proc, (unsigned long)proto->mprotect.addr);
	int prot = proto->mprotect.prot;
	int ret = 0;

	if (!vma || (end > vma->end) || !vma->anon) {
		ret = -EINVAL;
		goto out;
	}

	if (prot & PROT_EXEC)
		vma->perm |= KOBJ_RIGHT_EXEC;
	if (prot & PROT_WRITE)
		vma->perm |= KOBJ_RIGHT_WRITE;
	if (prot & PROT_READ)
		vma->perm |= KOBJ_RIGHT_READ;
out:
	return kobject_reply_errcode(proc->proc_handle, proto->token, ret);
}

static int get_fault_addr(struct process *proc, unsigned long virt, int *perm)
{
	struct vma *vma;

	/*
	 * check the address is stack or heap or mmap.
	 */
	if ((virt >= proc->brk_start) && (virt < proc->brk_cur)) {
		*perm = KR_RWX;
		return 0;
	}

	vma = &proc->anon_stack_vma;
	if ((virt >= vma->start) && (virt < vma->end)) {
		*perm = vma->perm;
		return virt;
	}

	vma = find_vma(proc, virt);
	if (!vma || !vma->anon)
		return -ENOENT;
	*perm = vma->perm;

	return 0;
}

static void page_fault_ack(struct process *proc, int ret, long token)
{
	/*
	 * if the page fault handle is fail the process will
	 * be killed. otherwise the releated task will be wake
	 * up.
	 */
	ret = (ret == 0) ? 0 : proc->proc_handle;
	kobject_reply_errcode(proc->proc_handle, token, ret);
}

long handle_user_page_fault(struct process *proc, uint64_t virt_addr,
		unsigned long info, long token)
{
	unsigned long start = PAGE_ALIGN(virt_addr);
	int ret, perm = 0, right = info & KOBJ_RIGHT_MASK;

	ret = get_fault_addr(proc, start, &perm);
	if (ret) {
		pr_err("can not get fault address 0x%lx for %d\n",
				virt_addr, proc_pid(proc));
		goto out;
	}

	if ((right & perm) != right) {
		ret = -EPERM;
		pr_err("P%d page fault 0x%lx %ld\n", proc_pid(proc), virt_addr, info);
		goto out;
	}

	ret = sys_map(proc->proc_handle, -1, start, PAGE_SIZE, perm);
	if (ret) {
		pr_err("map memory for process %d at 0x%lxfailed\n",
				proc_pid(proc), virt_addr);
	}

out:
	page_fault_ack(proc, ret, token);
	return ret;;
}

void vspace_init(struct process *proc, unsigned long elf_end)
{
	struct vma *vma;

	init_list(&proc->vma_free);
	init_list(&proc->vma_used);

	vma = kzalloc(sizeof(struct vma));
	if (!vma) {
		pr_err("vma init fail for proc\n");
		return;
	}

	/*
	 * mmap region
	 */
	vma->start = PROCESS_MMAP_BOTTOM;
	vma->end = PROCESS_MMAP_TOP;
	list_add(&proc->vma_free, &vma->list);

	/*
	 * brk region
	 */
	proc->brk_start = PAGE_BALIGN(elf_end);
	proc->brk_end = PROCESS_BRK_TOP;
	proc->brk_cur = proc->brk_start;
	assert(proc->brk_end > proc->brk_start);
}

static int elf_vma_init(struct process *proc, int elf_pma,
		unsigned long ebase, size_t esize)
{
	struct vma *vma = &proc->elf_vma;

	vma->start = ebase;
	vma->end = ebase + esize;
	vma->anon = 0;
	vma->perm = KR_RWX;
	vma->pma_handle = elf_pma;

	if (vma->pma_handle <= 0) {
		vma->pma_handle = create_pma(PMA_TYPE_NORMAL, vma->perm, 0, esize);
		if (vma->pma_handle <= 0)
			return -ENOMEM;
	}

	return sys_map(proc->proc_handle, vma->pma_handle,
			ebase, esize, vma->perm);
}

static int stack_vma_init(struct process *proc)
{
	struct vma *vma = &proc->init_stack_vma;
	int ret;

	vma->start = PROCESS_STACK_INIT_BASE;
	vma->end = PROCESS_STACK_INIT_BASE + PROCESS_STACK_INIT_SIZE;
	vma->anon = 0;
	vma->perm = KR_RW;

	vma->pma_handle = create_pma(PMA_TYPE_NORMAL, vma->perm,
			0, PROCESS_STACK_INIT_SIZE);
	if (vma->pma_handle <= 0)
		return -ENOMEM;

	ret = sys_map(proc->proc_handle, vma->pma_handle,
			PROCESS_STACK_INIT_BASE,
			PROCESS_STACK_INIT_SIZE,
			vma->perm);
	if (ret)
		return ret;

	vma = &proc->anon_stack_vma;
	vma->start = PROCESS_STACK_BASE;
	vma->end = PROCESS_STACK_BASE + (PROCESS_STACK_SIZE -
			PROCESS_STACK_INIT_SIZE);
	vma->anon = 1;
	vma->perm = KR_RW;

	return 0;
}

int process_mm_init(struct process *proc, int elf_pma,
		unsigned long elf_base, size_t elf_size)
{
	vspace_init(proc, elf_base + elf_size);

	if (elf_vma_init(proc, elf_pma, elf_base, elf_size)) {
		pr_err("init elf vma for process failed\n");
		return -ENOMEM;
	}

	if (stack_vma_init(proc)) {
		pr_err("init stack vma for process failed\n");
		return -ENOMEM;
	}

	return 0;
}
