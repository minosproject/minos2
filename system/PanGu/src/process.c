/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/epoll.h>

#include <minos/kobject.h>
#include <minos/map.h>
#include <minos/debug.h>
#include <minos/list.h>
#include <minos/kmalloc.h>
#include <minos/proto.h>

#include <pangu/vma.h>
#include <pangu/proc.h>
#include <pangu/ramdisk.h>
#include <pangu/elf.h>
#include <pangu/resource.h>
#include <pangu/request.h>

static struct process proc_self;
struct process *self = &proc_self;
LIST_HEAD(process_list);

extern int load_process_from_file(struct process *proc,
		struct elf_ctx *ctx, FILE *file);

extern int elf_init(struct elf_ctx *ctx, FILE *file);

struct process *find_process_by_name(const char *name)
{
	struct process *proc;

	list_for_each_entry(proc, &process_list, list) {
		if (strcmp(proc->name, name) == 0)
			return proc;
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
		.name = name;
	};

	if (flags & TASK_FLAGS_DEDICATED_HEAP)
		right |= KOBJ_RIGHT_HEAP_SELFCTL;

	return kobject_create(KOBJ_TYPE_PROCESS, right,
			KR_RC, (unsigned long)&args);
}

static int prepare_driver_resource(struct process *proc)
{
	struct resource *resource = proc->resource;

	while (resource) {
		resource->client = grant(proc->proc_handle,
				resource->handle, RES_DEFAULT_RIGHT);
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

	proc = kzalloc(sizeof(struct process) + strlen(name) + 1);
	if (!proc)
		return NULL;

	proc->proc_handle = -1;
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

	register_request_entry(REQUEST_TYPE_PROCESS, proc->proc_handle, proc);

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
	int fuxi;

	NEW_AUX_ENT(auxp, AT_NULL, 0);
	NEW_AUX_ENT(auxp, AT_PAGESZ, PAGE_SIZE);
	NEW_AUX_ENT(auxp, AT_HWCAP, 0);		// TBD cpu feature.

	/*
	 * pass the fuxi handle to this process, so it can connect
	 * to the service center. here will not check the return
	 * value, libc should check it ?
	 */
	if (fuxi_handle > 0) {
		fuxi = grant(proc->proc_handle, fuxi_handle, KR_WC);
		NEW_AUX_ENT(auxp, AT_ROOTFS_HANDLE, fuxi);
	}

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

static char *file_path_to_proc_name(char *path)
{
	return path;
}

static int setup_process(struct process *proc, char *path,
		struct elf_ctx *ctx, int argc, char **argv)
{
	struct vma *stack_vma = proc->stack_vma;
	void *stack, *origin, *tmp;
	char **new_argv;
	int i, ret = 0;
	char *name;

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

	name = file_path_to_proc_name(path);
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

static int load_process(char *path, int argc, char **argv,
		unsigned long flags, void *pdata)
{
	FILE *file = fopen(path, "r");
	struct process *proc;
	struct elf_ctx ctx;
	int ret;

	if (!file)
		return -ENOENT;

	ret = elf_init(&ctx, file);
	if (ret)
		return ret;

	proc = create_new_process(&ctx, path, flags, pdata);
	if (!proc)
		return -ENOMEM;

	ret = load_process_from_file(proc, &ctx, file);
	if (ret) {
		fclose(file);
		release_process(proc);
		return ret;
	}

	ret = setup_process(proc, path, &ctx, argc, argv);
	if (ret) {
		fclose(file);
		release_process(proc);
		return ret;
	}

	list_add_tail(&process_list, &proc->list);

	return 0;
}

struct process *load_ramdisk_process(char *path, int argc, char **argv,
		unsigned long flags, void *pdata)
{
	struct process *proc;
	struct ramdisk_file rfile;
	int ret;
	struct elf_ctx ctx;

	ret = ramdisk_open(path, &rfile);
	if (ret)
		return NULL;

	ret = elf_init_ramdisk(&ctx, &rfile);
	if (ret)
		return NULL;

	proc = create_new_process(&ctx, path, flags, pdata);
	if (!proc)
		return NULL;

	ret = load_process_from_ramdisk(proc, &ctx, &rfile);
	if (ret) {
		release_process(proc);
		return NULL;
	}

	/*
	 * all the resource is ok now, setup the process
	 * to prepare run it.
	 */
	ret = setup_process(proc, path, &ctx, argc, argv);
	if (ret) {
		release_process(proc);
		return NULL;
	}

	list_add_tail(&process_list, &proc->list);

	return proc;
}

void wakeup_process(struct process *proc)
{
	kobject_ctl(proc->proc_handle, KOBJ_PROCESS_WAKEUP, 0);
}

void self_init(unsigned long vma_base, unsigned long vma_end)
{
	/*
	 * init the root service
	 */
	struct vma *vma;

	init_list(&self->vma_free);
	init_list(&self->vma_used);
	self->pid = 1;
	self->proc_handle = 0;
	list_add_tail(&process_list, &self->list);

	vma = kzalloc(sizeof(struct vma));
	if (!vma)
		exit(-ENOMEM);

	vma->start = vma_base;
	vma->end = vma_end;
	list_add(&self->vma_free, &vma->list);
}

struct process *get_process_by_handle(int handle)
{
	struct process *proc = NULL;

	list_for_each_entry(proc, &process_list, list) {
		if (proc->proc_handle == handle)
			return proc;
	}

	return NULL;
}

static long handle_process_page_fault(struct process *proc,
		uint64_t virt_addr, int access_type, int tid)
{
	unsigned long start = PAGE_ALIGN(virt_addr);
	struct vma *vma;

	vma = find_vma(proc, start);
	if (!vma || !vma->anon)
		goto out;

	if (start + PAGE_SIZE >= vma->end)
		goto out;

	if (sys_map(proc->proc_handle, -1, start, PAGE_SIZE, KOBJ_RIGHT_RWX)) {
		pr_err("map memory for process %d failed\n", proc->pid);
		goto out;
	}

out:
	/*
	 * kill this process, TBD, use wake up
	 */
	pr_err("process %d access invalid address");
	return -EFAULT;
}

static long handle_process_exit(struct process *proc, uint64_t data0)
{
	return 0;
}

static inline int execv_argv_is_ok(char *argv, int max_size)
{
	int i;

	for (i = 0; i < max_size; i++) {
		if (argv[i] == 0)
			return 1;
	}

	return 0;
}

static long process_execv_handler(struct process *proc, struct proto *proto, void *data)
{
	struct execv_extra *extra = data;
	char **argv = extra->argv;
	unsigned long limit;
	char *string;
	int i;

	limit = PAGE_SIZE - sizeof(struct execv_extra);
	string = extra->buf;
	extra->path[FILENAME_MAX - 1] = 0;

	for (i = 0; i < extra->argc; i++) {
		if ((unsigned long)argv[i] >= limit)
			goto out;

		if (!execv_argv_is_ok(string + (unsigned long)argv[i],
					limit - (unsigned long)argv[i]))
			goto out;

		argv[i] = string + (unsigned long)argv[i];
	}

	return load_process(extra->path, extra->argc, extra->argv, 0, NULL);

out:
	return -EINVAL;
}

static long process_mmap_handler(struct process *proc, struct proto *proto, void *data)
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

	if (perm == KOBJ_RIGHT_NONE)
		pr_warn("request memory with no right\n");

	len = BALIGN(len, PAGE_SIZE);
	vma = request_vma(proc, 0, len, perm, 1);
	if (vma)
		addr = (void *)vma->start;

out:
	return (long)addr;
}

static long process_iamok_handler(struct process *proc, struct proto *proto, void *data)
{
	return 0;
}

static void handle_process_kernel_request(struct process *proc, struct epoll_event *event)
{
	switch (event->data.type) {
	case EPOLL_KEV_PAGE_FAULT:
		handle_process_page_fault(proc, event->data.data0,
				(int)event->data.data1, (int)event->data.data2);
		break;
	case EPOLL_KEV_PROCESS_EXIT:
		handle_process_exit(proc, event->data.data0);
		break;
	default:
		pr_err("unknown request from kernel %d\n", event->data.type);
		break;
	}
}

static void handle_process_in_request(struct process *proc, struct epoll_event *event)
{
	struct proto proto;
	static void *data = NULL;
	long ret;

	if (data == NULL) {
		data = get_pages(1);
		if (data == NULL)
			exit(-ENOMEM);
	}

	ret = kobject_read_proto_with_string(proc->proc_handle,
			&proto, data, PAGE_SIZE, 0);
	if (ret < 0)
		return;

	switch (proto.proto_id) {
	case PROTO_MMAP:
		ret = process_mmap_handler(proc, &proto, data);
		break;
	case PROTO_EXECV:
		ret = process_execv_handler(proc, &proto, data);
		break;
	case PROTO_IAMOK:
		ret = process_iamok_handler(proc, &proto, data);
		break;
	default:
		ret = -EPROTONOSUPPORT;
		break;
	}

	kobject_reply_errcode(proc->proc_handle, 0, ret);
}

void handle_process_request(struct epoll_event *event, struct request_entry *re)
{
	struct process *proc = (struct process *)re->data;

	switch (event->events) {
	case EPOLLIN:
		handle_process_in_request(proc, event);
		break;
	case EPOLLKERNEL:
		handle_process_kernel_request(proc, event);
		break;
	default:
		pr_err("invalid event for process\n");
		break;
	}
}
