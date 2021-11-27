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
#include <assert.h>

#include <minos/kobject.h>
#include <minos/map.h>
#include <minos/debug.h>
#include <minos/list.h>
#include <minos/proto.h>

#include <pangu/kmalloc.h>
#include <pangu/proc.h>
#include <pangu/ramdisk.h>
#include <pangu/elf.h>
#include <pangu/mm.h>

struct execv_request {
	int pma_handle;
	char *name;
	struct process *parent;
	uint64_t token;
	uint64_t reply_token;
	void *data;
	struct list_head list;
};

struct nvwa_proto {
	char path[FILENAME_MAX];
	uint64_t token;
	int pma_handle;
};

static LIST_HEAD(execv_request_list);
static char proto_buf[PAGE_SIZE];
static char argv_buf[512];

static struct process proc_self;
struct process *self = &proc_self;

static pid_t init_pid;

static LIST_HEAD(user_proc_list);

static void release_process(struct process *proc);

static int sys_create_process(int pid, unsigned long entry,
		unsigned long stack, int aff,
		int prio, unsigned long flags)
{
	struct process_create_arg args = {
		.entry = entry,
		.stack = stack,
		.aff = aff,
		.prio = prio,
		.flags = flags & TASK_FLAGS_KERNEL_MASK,
		.pid = pid,
	};

	return kobject_create(KOBJ_TYPE_PROCESS, (unsigned long)&args);
}

static struct process *create_new_process(char *name,
		struct process *parent, unsigned long entry,
		int elf_pma, unsigned long elf_base,
		size_t elf_size, int flags)
{
	struct process *proc;

	proc = kzalloc(sizeof(struct process));
	if (!proc)
		return NULL;

	proc->pinfo = alloc_procinfo(name, flags);
	if (!proc->pinfo) {
		kfree(proc);
		return NULL;
	}

	proc->proc_handle = sys_create_process(proc->pinfo->pid,
			entry, PROCESS_STACK_BASE, -1, -1, flags);
	if (proc->proc_handle <= 0) {
		kfree(proc);
		return NULL;
	}

	if (process_mm_init(proc, elf_pma, elf_base, elf_size))
		goto err_out;

	/*
	 * add the process to the process tree.
	 */
	init_list(&proc->wait_head);
	init_list(&proc->children);
	proc->parent = parent ? parent : self;
	list_add_tail(&parent->children, &proc->clist);

	if (proc_pid(proc->parent) == init_pid)
		list_add_tail(&user_proc_list, &proc->list);

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

static void *setup_auxv(struct process *proc, void *top, int flags)
{
	Elf64_auxv_t *auxp = (Elf64_auxv_t *)top;
	int fuxi, chiyou;

	NEW_AUX_ENT(auxp, AT_NULL, 0);
	NEW_AUX_ENT(auxp, AT_PAGESZ, PAGE_SIZE);
	NEW_AUX_ENT(auxp, AT_HWCAP, 0);		// TBD cpu feature.

	/*
	 * pass the fuxi handle to this process, so it can connect
	 * to the service center. here will not check the return
	 * value, libc should check it ?
	 */
	if (fuxi_handle > 0) {
		fuxi = grant(proc->proc_handle, fuxi_handle, KR_W);
		if (fuxi <= 0)
			pr_err("grant fuxi handle to process fail\n");
		else
			NEW_AUX_ENT(auxp, AT_ROOTFS_HANDLE, fuxi);
	}

	if ((chiyou_handle > 0) && (flags & TASK_FLAGS_DRV)) {
		chiyou = grant(proc->proc_handle, chiyou_handle, KR_W);
		if (chiyou <= 0)
			pr_err("grant chiyou handle to process fail\n");
		else
			NEW_AUX_ENT(auxp, AT_CHIYOU_HANDLE, chiyou);
	}

	return (void *)auxp;
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

	/*
	 * add process name to the latest argv in the buffer.
	 */
	stack = set_argv_string(stack, cnt++, new_argv, NULL, name);
	*argc = cnt;

	return stack;
}

static char *file_path_to_proc_name(char *path)
{
	char *name = strrchr(path, '/');

	if (name == NULL)
		return path;
	else
		return name + 1;
}

static int setup_process(struct process *proc, char *path,
		int argc, char **argv, int flags)
{
	struct vma *stack_vma = &proc->init_stack_vma;
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
	stack = prepare_process_argv(proc, name, stack, &argc, argv, new_argv);
	if (stack == NULL) {
		ret = -ENOMEM;
		goto err_setup_argv;
	}

	/*
	 * convert the memory address of argv to the process's
	 * stack address.
	 */
	for (i = 0; i < argc; i++) {
		new_argv[i] = (char *)PROCESS_STACK_TOP -
			((char *)origin - new_argv[i]);
		pr_debug("argv address is %p\n", new_argv[i]);
	}

	stack = setup_auxv(proc, stack, proc->pinfo->flags);
	stack = setup_envp(stack);
	stack = setup_argv(stack, argc, new_argv);

	/*
	 * update the new stack pointer for the process.
	 */
	kobject_ctl(proc->proc_handle, KOBJ_PROCESS_SETUP_SP,
			PROCESS_STACK_TOP - (origin - stack));

err_setup_argv:
	unmap_self_memory(tmp);
err_map_stack_mem:
	free_pages(new_argv);

	return ret;
}

static int setup_process_handles(struct process *proc, char *buf,
		struct handle_desc *hdesc, int num_handle)
{
	int *htarget;
	char *tmp;
	int i, size;

	if (num_handle <= 0 || !hdesc)
		return 0;

	htarget = kzalloc(sizeof(int) * num_handle);
	if (!htarget)
		return -ENOMEM;

	for (i = 0; i < num_handle; i++) {
		htarget[i] = grant(proc->proc_handle,
				hdesc[i].handle, hdesc[i].right);
		if (htarget[i] <= 0) {
			pr_err("grant %d to process %s failed\n",
					hdesc[i].handle, proc->pinfo->cmd);
		}
	}

	size = sprintf(buf, "%s", "handle@");
	tmp = buf + size;

	for (i = 0; i < num_handle; i++) {
		if (i == (num_handle - 1))
			size = sprintf(tmp, "%d", htarget[i]);
		else
			size = sprintf(tmp, "%d,", htarget[i]);
		tmp += size;
	}

	*tmp = 0;
	pr_info("handle send to %s [%s]\n", proc->pinfo->cmd, buf);
	kfree(htarget);

	return 1;
}

struct process *load_ramdisk_process(char *path,
		struct handle_desc *hdesc,
		int num_handle, int flags)
{
	struct process *proc;
	struct ramdisk_file rfile;
	struct elf_ctx ctx;
	char *argv[2] = {argv_buf, NULL};
	int ret;

	ret = ramdisk_open(path, &rfile);
	if (ret) {
		pr_err("can not find %s in ramdisk\n", path);
		return NULL;
	}

	ret = elf_init_ramdisk(&ctx, &rfile);
	if (ret)
		return NULL;

	proc = create_new_process(path, self, ctx.ehdr.e_entry, 0,
			ctx.base_load_vbase, ctx.memsz, flags);
	if (!proc)
		return NULL;

	ret = load_process_from_ramdisk(proc, &ctx, &rfile);
	if (ret) {
		release_process(proc);
		return NULL;
	}

	/*
	 * all the resource is ok now, setup the process
	 * to prepare run it. before setup the argv, need to pass
	 * the handle to the process, which are needed for this
	 * process.
	 */
	ret = setup_process_handles(proc, argv_buf, hdesc, num_handle);
	if (ret < 0) {
		pr_err("setup process handles fail\n");
		goto out_err;
	}

	ret = setup_process(proc, path, ret, argv, proc->pinfo->flags);
	if (ret) {
		pr_err("set up process failed\n");
		goto out_err;
	}

	/*
	 * keep this action as the latest step.
	 */
	ret = register_request_entry(proc->proc_handle, proc);
	if (ret) {
		pr_err("listen to process failed\n");
		goto out_err;
	}

	return proc;

out_err:
	release_process(proc);
	return NULL;
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

	self->pinfo = alloc_procinfo("pangu.srv", TASK_FLAGS_SRV);
	assert(self->pinfo != NULL);
	assert(self->pinfo->pid == 0);

	init_list(&self->vma_free);
	init_list(&self->vma_used);
	init_list(&self->children);
	init_list(&self->wait_head);
	self->proc_handle = 0;

	vma = kzalloc(sizeof(struct vma));
	if (!vma)
		exit(-ENOMEM);

	vma->start = vma_base;
	vma->end = vma_end;
	list_add(&self->vma_free, &vma->list);
}

static void proc_mm_deinit(struct process *proc)
{
	struct vma *vma, *tmp;

	list_for_each_entry_safe(vma, tmp, &proc->vma_free, list) {
		list_del(&vma->list);
		kfree(vma);
	}

	list_for_each_entry_safe(vma, tmp, &proc->vma_used, list) {
		list_del(&vma->list);
		kfree(vma);
	}

	kobject_close(proc->elf_vma.pma_handle);
	kobject_close(proc->init_stack_vma.pma_handle);
}

static void finish_wait(struct process * proc, long data0)
{
	struct process *parent = proc->parent;
	struct wait_entry *entry, *tmp;

	/*
	 * wake up the task which waitting for this proc.
	 */
	list_for_each_entry_safe(entry, tmp, &parent->wait_head, list) {
		if ((entry->type == PROC_WAIT_ANY) ||
				(entry->pid == proc->pinfo->pid)) {
			list_del(&entry->list);
			kobject_reply_errcode(parent->proc_handle,
					entry->token, proc->pinfo->pid);
			kfree(entry);
		}
	}

	/*
	 * release the wait entry which the proc wait.
	 */
	list_for_each_entry_safe(entry, tmp, &proc->wait_head, list) {
		list_del(&entry->list);
		kfree(entry);
	}
}

static void deal_with_child_process(struct process *proc)
{
	struct process *parent = proc->parent;
	struct process *child, *tmp;

	list_for_each_entry_safe(child, tmp, &proc->children, clist) {
		list_del(&child->clist);
		list_add_tail(&parent->children, &child->clist);
		child->parent = parent;
	}
}

static void __release_process(struct process *proc, int kill)
{
	int proc_handle;

	if (!proc)
		return;

	proc_handle = proc->proc_handle;
	unregister_request_entry(proc_handle, proc);
	proc_mm_deinit(proc);
	release_procinfo(proc->pinfo);
	kfree(proc);

	/*
	 * if the process is killed by pangu process, the kernel
	 * will call kobject_put, and will not get the event when
	 * kernel release the process.
	 */
	if ((proc_handle > 0) && !kill)
		kobject_close(proc_handle);
}

static void release_process(struct process *proc)
{
	return __release_process(proc, 0);
}

static void handle_init_process_exit(struct process *proc)
{
	/*
	 * if the init process exit(), system will reboot.
	 */
	pr_err("init process exit, reboot system\n");
	exit(-1);
}

static long handle_process_exit(struct process *proc, uint64_t data0)
{
	/*
	 * if the init process was exited, kill all the process and
	 * then relaunch the init process.
	 */
	if (proc_pid(proc) == init_pid) {
		handle_init_process_exit(proc);
	} else {
		finish_wait(proc, data0);
		deal_with_child_process(proc);
	}

	release_process(proc);

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

static inline struct execv_request *alloc_execv_request(void *data)
{
	struct execv_request *er;

	er = kzalloc(sizeof(struct execv_request));
	if (!er)
		return NULL;

	er->data = get_pages(1);
	if (!er->data) {
		kfree(er);
		return NULL;
	}

	memcpy(er->data, data, PAGE_SIZE);

	return er;
}

static inline void free_execv_request(struct execv_request *er)
{
	free_pages(er->data);
	free(er);
}

static int send_elf_load_request(struct process *proc, const char *path, struct execv_request *er)
{
	struct nvwa_proto proto;
	static uint64_t nvwa_token = 0;
	int ret;

	/*
	 * create an empty PMA handle for the target process, then
	 * grant the pma handle to the nvwa process, so that nvwa
	 * can allocate memory for the elf file.
	 */
	er->pma_handle = create_pma(PMA_TYPE_NORMAL, KR_RWX, 0, 0);
	if (er->pma_handle <= 0)
		return er->pma_handle;

	proto.pma_handle = grant(nvwa_proc->proc_handle, er->pma_handle, KR_RWC);
	if (proto.pma_handle <= 0) {
		kobject_close(er->pma_handle);
		return proto.pma_handle;
	}

	strcpy(proto.path, path);
	er->parent = proc;
	er->token = proto.token = nvwa_token++;

	ret = kobject_write(nvwa_handle, &proto,
			sizeof(struct nvwa_proto), NULL, 0, 2000);
	if (ret == 0)
		list_add_tail(&execv_request_list, &er->list);

	return ret;
}

static long pangu_execv(struct process *proc, struct proto *proto, void *data)
{
	struct execv_extra *extra = data;
	int *argv_off = extra->argv;
	struct execv_request *er;
	unsigned long limit;
	int i, ret = -EINVAL;
	char *string;

	limit = PAGE_SIZE - sizeof(struct execv_extra);
	string = extra->buf;
	extra->path[FILENAME_MAX - 1] = 0;

	for (i = 0; i < extra->argc; i++) {
		if (argv_off[i] >= limit)
			goto out;
		if (!execv_argv_is_ok(string + argv_off[i], limit - argv_off[i]))
			goto out;
	}

	/*
	 * the execv value is correct, then send the elf load
	 * request to nvwa process.
	 */
	er = alloc_execv_request(data);
	if (!er) {
		ret = -ENOMEM;
		goto out;
	}

	/*
	 * copy the reply token, so after the elf image has
	 * been loaded, can be reply to the task correctly.
	 */
	er->reply_token = proto->token;

	ret = send_elf_load_request(proc, extra->path, er);
	if (ret)
		goto out_release_er;

	return 0;

out_release_er:
	free_execv_request(er);
out:
	return kobject_reply_errcode(proc->proc_handle, proto->token, ret);
}

static void load_init_process(void)
{
	struct execv_extra *extra = (struct execv_extra *)proto_buf;
	struct proto proto;

	memset(&proto, 0, sizeof(struct proto));
	memset(extra, 0, sizeof(struct execv_extra));
	pr_info("loading init shell.app ...\n");
	strcpy(extra->path, "/c/bin/shell.app");

	assert(!pangu_execv(self, &proto, extra));
}

static void notify_chiyou_service(void)
{
	struct proto proto;

	proto.proto_id = PROTO_ROOTFS_READY;
	kobject_write(chiyou_handle, &proto, sizeof(struct proto), NULL, 0, -1);
}

static long pangu_iamok(struct process *proc, struct proto *proto, void *data)
{
	/*
	 * start the init process, current start the shell process.
	 */
	if (proc == rootfs_proc) {
		load_init_process();
		notify_chiyou_service();
	}

	return kobject_reply_errcode(proc->proc_handle, proto->token, 0);
}

static void handle_process_kernel_request(struct process *proc, struct epoll_event *event)
{
	switch (event->data.type) {
	case EPOLL_KEV_PAGE_FAULT:
		handle_user_page_fault(proc, event->data.data0,
				(unsigned long)event->data.data1,
				(long)event->data.data2);
		break;
	case EPOLL_KEV_PROCESS_EXIT:
		handle_process_exit(proc, event->data.data0);
		break;
	default:
		pr_err("unknown request from kernel %d\n", event->data.type);
		break;
	}
}

static int __do_execv(struct proto *proto, struct execv_request *er)
{
	struct execv_extra *extra = er->data;
	int i, ret = -EINVAL, flags;
	struct process *new;
	char *string;
	char **argv;

	argv = kzalloc(sizeof(char *) * extra->argc);
	if (!argv)
		return -ENOMEM;

	/*
	 * only chiyou service can load the driver process
	 * now.
	 */
	flags = extra->flags;
	if (er->parent != chiyou_proc)
		flags &= ~TASK_FLAGS_DRV;

	/*
	 * do not need to check again, since these content
	 * has been checked in handle execv function.
	 */
	string = extra->buf;
	for (i = 0; i < extra->argc; i++) {
		argv[i] = string + (unsigned long)argv[i];
		pr_debug("argv %d is 0x%p\n", i, argv[i]);
	}

	new = create_new_process(extra->path, er->parent, proto->elf_info.entry,
			er->pma_handle, proto->elf_info.elf_base,
			proto->elf_info.elf_size, flags);
	if (!new)
		return -ENOMEM;

	ret = setup_process(new, extra->path, extra->argc, argv, flags);
	if (ret) {
		release_process(new);
		return ret;
	}

	register_request_entry(new->proc_handle, new);
	wakeup_process(new);
	kfree(argv);

	return new->pinfo->pid;
}

static int do_execv(struct proto *proto, struct execv_request *er)
{
	int ret = __do_execv(proto, er);

	/*
	 * pangu will launch the init process only, so record
	 * the pid of the init process, once the init process
	 * is died, launched it again.
	 */
	if (er->parent == self) {
		init_pid = ret;
		return 0;
	}

	return kobject_reply_errcode(er->parent->proc_handle, er->reply_token, ret);
}

static long pangu_elf_info(struct process *proc, struct proto *proto, void *data)
{
	struct execv_request *er, *next;

	/*
	 * reply nvwa service.
	 */
	if (proc != nvwa_proc) {
		pr_err("not nvwa proc %s\n", proc->pinfo->cmd);
		return kobject_reply_errcode(proc->proc_handle, proto->token, -EPERM);
	} else {
		kobject_reply_errcode(proc->proc_handle, proto->token, 0);
	}

	/*
	 * do handle the execv request.
	 */
	list_for_each_entry_safe(er, next, &execv_request_list, list) {
		if (er->token != proto->elf_info.token)
			continue;

		list_del(&er->list);
		if (proto->elf_info.ret_code != 0) {
			pr_err("nvwa load elf failed\n");
			kobject_reply_errcode(er->parent->proc_handle,
					er->reply_token, proto->elf_info.ret_code);
			return -EPERM;
		}

		return do_execv(proto, er);
	}

	pr_err("handle_nvwa_request fail no such request\n");
	return -ENOENT;
}

static long pangu_waitpid(struct process *proc, struct proto *proto, void *data)
{
	int pid = proto->waitpid.pid;
	struct process *child;
	struct wait_entry *we;
	int found = 0;
	int ret;

	if ((pid != -1) && (pid <= 0)) {
		pr_err("waitpid do not support such mode\n");
		ret = -ENOENT;
		goto fail;
	}

	if (pid > 0) {
		list_for_each_entry(child, &proc->children, clist) {
			if (child->pinfo->pid == pid) {
				found = 1;
				break;
			}
		}
	}

	if (!found) {
		ret = -ENOENT;
		goto fail;
	}

	we = kzalloc(sizeof(struct wait_entry));
	if (!we) {
		ret = - ENOMEM;
		goto fail;
	}

	we->type = (pid == -1) ? PROC_WAIT_ANY : PROC_WAIT_PID;
	we->pid = pid;
	we->token = proto->token;
	list_add_tail(&proc->wait_head, &we->list);

	return 0;
fail:
	return kobject_reply_errcode(proc->proc_handle, proto->token, ret);
}

static syscall_hdl proc_syscall_handles[] = {
	[0 ... PROTO_PROC_ID_MAX] = NULL,
	[PROTO_IAMOK_ID]	= pangu_iamok,
	[PROTO_ELF_INFO_ID]	= pangu_elf_info,
	[PROTO_MMAP_ID]		= pangu_mmap,
	[PROTO_EXECV_ID]	= pangu_execv,
	[PROTO_BRK_ID]		= pangu_brk,
	[PROTO_PROCCNT_ID]	= pangu_proccnt,
	[PROTO_TASKSTAT_ID]	= pangu_taskstat,
	[PROTO_PROCINFO_ID]	= pangu_procinfo,
	[PROTO_MPROTECT_ID]	= pangu_mprotect,
	[PROTO_WAITPID_ID]	= pangu_waitpid,
};

static void handle_process_in_request(struct process *proc, struct epoll_event *event)
{
	struct proto proto;
	long ret;

	ret = sys_read_proto(proc->proc_handle, &proto, proto_buf, PAGE_SIZE, 0);
	if (ret < 0)
		return;

	if ((proto.proto_id >= PROTO_PANGU_END) ||
			!proc_syscall_handles[proto.proto_id - PROTO_IAMOK]) {
		kobject_reply_errcode(proc->proc_handle, proto.token, -ENOSYS);
		return;
	}

	ret = proc_syscall_handles[proto.proto_id - PROTO_IAMOK](proc, &proto, proto_buf);
	if (ret)
		pr_err("handle syscall failed with %ld\n", ret);
}

void handle_process_request(struct epoll_event *event, struct process *proc)
{
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
