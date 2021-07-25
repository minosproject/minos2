/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <minos/kobject.h>
#include <minos/map.h>
#include <minos/debug.h>
#include <minos/list.h>
#include <minos/kmalloc.h>

#include <pangu/vma.h>
#include <pangu/proc.h>
#include <pangu/ramdisk.h>
#include <pangu/elf.h>
#include <pangu/resource.h>

static struct process proc_self;
struct process *self = &proc_self;
static LIST_HEAD(process_list);

struct process_proto {
	int req;
	union {
		char path[FILENAME_MAX]; // libc is 4096, will change to 256
	};
};

#define PROC_REQ_NONE		0x000
#define PROC_REQ_CREATE_PROCESS	0x100
#define PROC_REQ_GET_INFO	0x101

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

	ret = unmap(self->proc_handle, vma->pma_handle,
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
	ret = map(self->proc_handle, pma_handle, vma->start, size, perm);
	if (ret) {
		release_vma(self, vma);
		return NULL;
	}

	return (void *)vma->start;
}

static void process_init(struct process *proc)
{
	proc->proc_handle = -1;
	init_list(&proc->vma_free);
	init_list(&proc->vma_used);
}

static int process_vspace_init(struct process *proc, struct elf_ctx *ctx)
{
	struct vma *vma;

	vspace_init(proc);

	proc->elf_vma = request_vma(proc, ctx->base_load_vbase,
			ctx->memsz, KOBJ_RIGHT_RWX, 0);
	if (!proc->elf_vma)
		return -ENOMEM;

	proc->stack_vma = request_vma(proc, PROCESS_STACK_INIT_BASE,
			PROCESS_STACK_INIT_SIZE, KOBJ_RIGHT_RW, 0);
	if (!proc->stack_vma)
		return ENOMEM;

	/*
	 * request other stack region, which will page faulted.
	 */
	vma = request_vma(proc, PROCESS_STACK_BASE,
			PROCESS_STACK_SIZE - PROCESS_STACK_INIT_SIZE,
			KOBJ_RIGHT_RW, 1);
	if (!vma)
		return -ENOMEM;

	return 0;
}

void release_process(struct process *proc)
{

}

static int create_process(char *name, unsigned long entry,
		unsigned long stack, int aff,
		int prio, unsigned long flags)
{
	int right = KOBJ_RIGHT_CTL | KOBJ_RIGHT_RW;

	struct process_create_arg args = {
		.entry = entry,
		.stack = stack,
		.aff = aff,
		.prio = prio,
		.flags = flags & TASK_FLAGS_KERNEL_MASK,
	};

	if (flags & TASK_FLAGS_DEDICATED_HEAP)
		right |= KOBJ_RIGHT_HEAP_SELFCTL;

	return kobject_create(name, KOBJ_TYPE_PROCESS, right,
			KOBJ_RIGHT_CTL, (unsigned long)&args);
}

static int prepare_driver_resource(struct process *proc)
{
	struct resource *resource = proc->resource;

	while (resource) {
		resource->client = grant(proc->proc_handle,
				resource->handle, RES_DEFAULT_RIGHT, 0);
		if (resource->client <= 0)
			return -EIO;
		resource = resource->next;
	}

	return 0;
}

static struct process *create_new_process(struct elf_ctx *ctx,
		char *name, int flags, void *pdata)
{
	struct process *proc;

	proc = kzalloc(sizeof(struct process));
	if (!proc)
		return NULL;

	process_init(proc);
	proc->flags = flags;
	proc->pdata = pdata;

	proc->proc_handle = create_process(name, ctx->ehdr.e_entry, 
			PROCESS_STACK_BASE, -1, -1, flags);
	if (proc->proc_handle <= 0) {
		kfree(proc);
		return NULL;
	}
	proc->pid = kobject_ctl(proc->proc_handle, KOBJ_PROCESS_GET_PID, 0);

	if (process_vspace_init(proc, ctx))
		goto err_out;

	if (flags & TASK_FLAGS_DRV) {
		if (prepare_driver_resource(proc)) {
			pr_err("failed to setup the resource for driver\n");
			goto err_out;
		}
	}

	return proc;

err_out:
	release_process(proc);
	return NULL;
}

#define NEW_AUX_ENT(auxp, type, value)	\
	do {				\
		auxp--;			\
		auxp->a_type = type;	\
		auxp->a_val = value;	\
	} while (0)

static void *copy_argv_string(void *top, int i, char **argv, char *buf)
{
	int size;

	size = strlen(buf) + 1;
	size = BALIGN(size, sizeof(unsigned long));
	top -= size;
	strcpy((char *)top, buf);
	argv[i] = (char *)top;

	return top;
}

static void *set_argv_string(void *top, int i, char **argv,
		char *opt, char *arg)
{
	char buf[256];

	if (opt)
		sprintf(buf, "%s=%s", opt, arg);
	else
		sprintf(buf, "%s", arg);

	return copy_argv_string(top, i, argv, buf);
}

static void *setup_envp(void *top)
{
	top -= sizeof(unsigned long);
	*(char **)top = NULL;

	return top;
}

static void *setup_argv(void *top, int argc, char **argv)
{
	char **str = (char **)top;
	int i;

	str--;
	*str = NULL;

	for (i = 0; i < argc; i++) {
		str--;
		*str = argv[i];
	}

	str--;
	*(unsigned long *)str = argc;

	return (void *)str;
}

#define NEW_AUX_ENT(auxp, type, value)	\
	do {				\
		auxp--;			\
		auxp->a_type = type;	\
		auxp->a_val = value;	\
	} while (0)

static void *setup_auxv(struct process *proc, void *top, unsigned long flags)
{
	Elf64_auxv_t *auxp = (Elf64_auxv_t *)top;
	extern unsigned long heap_base, heap_end;

	NEW_AUX_ENT(auxp, AT_NULL, 0);
	NEW_AUX_ENT(auxp, AT_PAGESZ, PAGE_SIZE);
	NEW_AUX_ENT(auxp, AT_HWCAP, 0);		// TBD cpu feature.

	if (flags & TASK_FLAGS_DEDICATED_HEAP) {
		NEW_AUX_ENT(auxp, AT_HEAP_BASE, heap_base);
		NEW_AUX_ENT(auxp, AT_HEAP_END, heap_end);
	}

	return (void *)auxp;
}

static void *prepare_driver_process_argv(struct process *proc,
		void *stack, char **argv, int *argc)
{
	struct resource *tmp = proc->resource;
	int irq_len = 4, mmio_len = 5, cnt = *argc;
	char mmio_buf[128];
	char irq_buf[128];

	strcpy(mmio_buf, "mmio@");
	strcpy(irq_buf, "irq@");

	while (tmp) {
		if (tmp->type == RES_TYPE_MMIO) {
			pr_debug("add mmio 0x%lx 0x%lx\n", tmp->start, tmp->end);
			mmio_len += sprintf(&mmio_buf[mmio_len], "%d,", tmp->client);
		} else if (tmp->type == RES_TYPE_IRQ) {
			pr_debug("add irq %d %d\n", tmp->start, tmp->end);
			irq_len += sprintf(&irq_buf[irq_len], "%d,", tmp->client);
		} else {
			pr_warn("resource do not support\n");
		}
		tmp = tmp->next;
	}

	/*
	 * remove the latest char ',' at mmio and irq string.
	 */
	mmio_buf[mmio_len - 1] = 0;
	irq_buf[irq_len - 1] = 0;
	stack = copy_argv_string(stack, cnt++, argv, mmio_buf);
	stack = copy_argv_string(stack, cnt++, argv, irq_buf);

	*argc = cnt;

	return stack;
}

static void *prepare_process_argv(struct process *proc, char *name,
		void *stack, int *argc, char **argv, char **new_argv)
{
	int i, cnt = *argc;

	/*
	 * the final argc will store to the argc, and all the argv
	 * will store to the new_argv.
	 */
	if (cnt > MAX_ARGC) {
		pr_err("argv is too big %d\n", cnt);
		return NULL;
	}

	/*
	 * copy the old argv to the new argv array, and store
	 * the string to the stack.
	 */
	for (i = 0; i < cnt; i++)
		stack = copy_argv_string(stack, i, new_argv, argv[i]);

	if (proc->flags & TASK_FLAGS_DRV) {
		stack = prepare_driver_process_argv(proc, stack, new_argv, &cnt);
		if (stack == NULL) {
			pr_err("copy argv to process failed\n");
			return NULL;
		}
	}

	/*
	 * add process name to the latest argv in the buffer.
	 */
	stack = set_argv_string(stack, cnt++, new_argv, NULL, name);
	*argc = cnt;

	return stack;
}

static int setup_process(struct process *proc, char *name,
		struct elf_ctx *ctx, int argc, char **argv)
{
	struct vma *stack_vma = proc->stack_vma;
	void *stack, *origin, *tmp;
	char **new_argv;
	int i, ret = 0;

	if (argc > MAX_ARGC) {
		pr_warn("argv is too long %d\n", argc);
		return -ENOSPC;
	}

	new_argv = (char **)get_page();
	if (!new_argv)
		return -ENOMEM;

	tmp = stack = map_self_memory(stack_vma->pma_handle,
			PROCESS_STACK_INIT_SIZE, KOBJ_RIGHT_RW);
	if (!stack) {
		ret = -ENOMEM;
		goto err_map_stack_mem;
	}

	stack += PROCESS_STACK_INIT_SIZE;
	origin = stack;

	stack = prepare_process_argv(proc, name,
			stack, &argc, argv, new_argv);
	if (stack == NULL)
		goto err_setup_argv;

	/*
	 * convert the memory address of argv to the process's
	 * stack address.
	 */
	for (i = 0; i < argc; i++) {
		new_argv[i] = (char *)PROCESS_STACK_TOP -
			((char *)origin - new_argv[i]);
		pr_info("address is %p\n", new_argv[i]);
	}

	stack = setup_auxv(proc, stack, proc->flags);
	stack = setup_envp(stack);
	stack = setup_argv(stack, argc, new_argv);

	/*
	 * update the new stack pointer for the process.
	 */
	kobject_ctl(proc->proc_handle, KOBJ_PROCESS_SETUP_SP,
			PROCESS_STACK_TOP - (origin - stack));

	unmap_self_memory(tmp);

	return 0;

err_setup_argv:
	unmap_self_memory(tmp);
err_map_stack_mem:
	free_pages(argv);

	return ret;
}

static char *file_path_to_proc_name(char *path)
{
	return path;
}

int load_ramdisk_process(char *path, int argc, char **argv,
		unsigned long flags, void *pdata)
{
	struct process *proc;
	struct ramdisk_file rfile;
	int ret;
	char *name;
	struct elf_ctx ctx;

	ret = ramdisk_open(path, &rfile);
	if (ret)
		return -ENOENT;

	ret = elf_init_ramdisk(&ctx, &rfile);
	if (ret)
		return ret;

	name = file_path_to_proc_name(path);
	proc = create_new_process(&ctx, name, flags, pdata);
	if (!proc)
		return -ENOMEM;

	ret = load_process_from_ramdisk(proc, &ctx, &rfile);
	if (ret) {
		release_process(proc);
		return ret;
	}

	/*
	 * all the resource is ok now, setup the process
	 * to prepare run it.
	 */
	ret = setup_process(proc, name, &ctx, argc, argv);
	if (ret) {
		release_process(proc);
		return ret;
	}

	list_add_tail(&process_list, &proc->list);

	return 0;
}

void wakeup_all_process(void)
{
	struct process *proc;

	list_for_each_entry(proc, &process_list, list) {
		if (proc->pid == 0)
			continue;
		kobject_ctl(proc->proc_handle, KOBJ_PROCESS_WAKEUP, 0);
	}
}

void self_init(unsigned long vma_base, unsigned long vma_end)
{
	/*
	 * init the root service
	 */
	struct vma *vma;

	process_init(self);
	list_add_tail(&process_list, &self->list);
	self->pid = 0;
	self->proc_handle = 0;

	vma = kzalloc(sizeof(struct vma));
	if (!vma)
		exit(-ENOMEM);

	vma->start = vma_base;
	vma->end = vma_end;
	list_add(&self->vma_free, &vma->list);
}

int handle_process_request(struct process_proto *proto)
{
	switch (proto->req) {
	case PROC_REQ_CREATE_PROCESS:
		break;
	case PROC_REQ_GET_INFO:
		break;
	default:
		break;
	}

	return 0;
}
