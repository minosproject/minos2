/*
 * Copyright (C) 2021 Min Le (lemin9538@163.com)
 */

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <assert.h>

#include <minos/kobject.h>
#include <minos/map.h>
#include <minos/debug.h>
#include <minos/list.h>
#include <minos/proto.h>
#include <minos/libc.h>
#include <minos/procinfo.h>

#include <uapi/bootdata.h>

#include <pangu/kmalloc.h>
#include <pangu/proc.h>
#include <pangu/bootarg.h>

int proc_epfd;
int fuxi_handle;
int nvwa_handle;
int chiyou_handle;

int setup_mem_handle;

struct process *rootfs_proc;
struct process *nvwa_proc;
struct process *chiyou_proc;
struct process *fuxi_proc;

unsigned long heap_base, heap_end;

extern void ramdisk_init(unsigned long base, unsigned long end);
extern void of_init(unsigned long base, unsigned long end);
extern void pangu_main(void);
extern void procfs_init(void);
extern void procinfo_init(int max_proc, int u, int t);

static struct bootdata *bootdata;
static char *rootfs_default = "rootfs.drv";

#define MAX_EVENT 16

int register_request_entry(int handle, struct process *proc)
{
       struct epoll_event event;

       event.events = EPOLLIN | EPOLLKERNEL;
       event.data.ptr = proc;

       return epoll_ctl(proc_epfd, EPOLL_CTL_ADD, handle, &event);
}

int unregister_request_entry(int handle, struct process *proc)
{
	struct epoll_event event;

	event.events = EPOLLIN | EPOLLKERNEL;
	event.data.ptr = proc;

	return epoll_ctl(proc_epfd, EPOLL_CTL_DEL, handle, &event);
}

static void handle_event(struct epoll_event *event)
{
	struct process *proc = event->data.ptr;

	if (!proc) {
		pr_err("invalid process event receive\n");
		return;
	}

	return handle_process_request(event, proc);
}

void pangu_main(void)
{
	struct epoll_event events[MAX_EVENT];
	long ret;
	int i;

	/*
	 * wake up all the process which created by PanGu itself.
	 * currently only need to wake up the rootfs driver process.
	 */
	wakeup_process(rootfs_proc);

	for (;;) {
		ret = epoll_wait(proc_epfd, events, MAX_EVENT, -1);
		if (ret <= 0 || ret > MAX_EVENT) {
			pr_err("failed wait for event try again %ld?\n", ret);
			continue;
		}

		for (i = 0; i < ret; i++)
			handle_event(&events[i]);
	}
}

static void get_boot_opt(char *str)
{
	char *pos, *left, *right;

	if (!str)
		return;

	pos = strchr(str, '=');
	if (pos == NULL)
		return;

	left = str;
	right = pos + 1;
	*pos = 0;

	if (strncmp(left, "bootdata", 8) == 0)
		bootdata = (struct bootdata *)strtol(right, NULL, 16);
}

static void dump_boot_info(void)
{
	pr_info("dtb     [0x%lx 0x%lx]\n",
                       bootdata->dtb_start, bootdata->dtb_end);
	pr_info("ramdisk [0x%lx 0x%lx]\n",
                       bootdata->ramdisk_start, bootdata->ramdisk_end);
	pr_info("vmap    [0x%lx 0x%lx]\n",
                       bootdata->vmap_start, bootdata->vmap_end);
	pr_info("heap    [0x%lx 0x%lx]\n",
                       bootdata->heap_start, bootdata->heap_end);

	pr_info("sys max proc %d\n", bootdata->max_proc);
	pr_info("uproc_info %d\n", bootdata->uproc_info_handle);
	pr_info("ktask_stat %d\n", bootdata->ktask_stat_handle);
}

static int start_and_wait_process(struct process *proc)
{
	struct proto proto;
	int ret;

	pr_info("Start %s and waitting ...\n", proc->pinfo->cmd);
	kobject_ctl(proc->proc_handle, KOBJ_PROCESS_WAKEUP, 0);

	for (;;) {
		ret = kobject_read_simple(proc->proc_handle, &proto,
				sizeof(struct proto), 0);
		if (ret > 0)
			break;

		if (ret != -EAGAIN)
			break;
	}

	if (ret < 0) {
		pr_info("Get response from %s fail %d\n", proc->pinfo->cmd, ret);
		return ret;
	}

	pr_info("Get response from %s service %d\n",
			proc->pinfo->cmd, proto.proto_id);
	if (proto.proto_id != PROTO_IAMOK)
		return -EPROTO;

	kobject_reply_errcode(proc->proc_handle, ret, 0);

	return 0;
}

static int load_nvwa_service(void)
{
	struct handle_desc hdesc[1];
	
	nvwa_handle = kobject_create_endpoint(0);
	if (nvwa_handle <= 0)
		return nvwa_handle;

	hdesc[0].handle = nvwa_handle;
	hdesc[0].right = KR_R;
	nvwa_proc = load_ramdisk_process("nvwa.srv", hdesc, 1, TASK_FLAGS_DRV);
	if (nvwa_proc == NULL)
		return -ENOMEM;

	kobject_ctl(nvwa_proc->proc_handle, KOBJ_PROCESS_GRANT_RIGHT, PROC_FLAGS_VMCTL);

	return start_and_wait_process(nvwa_proc);
}

static int load_chiyou_service(void)
{
	unsigned long pbase;
	struct pma_create_arg args;
	struct handle_desc hdesc[2];
	int handle;

	/*
	 * chiyou service will handle the dtb or setup
	 * data, each driver or service will get information
	 * from it.
	 */
	pbase = (unsigned long)kobject_ctl(0, KOBJ_PROCESS_VA2PA, bootdata->dtb_start);
	assert(pbase != -1);

	args.type = PMA_TYPE_PMEM;
	args.consequent = 0;
	args.start = pbase;
	args.size = bootdata->dtb_end - bootdata->dtb_start;
	args.right = KR_RW;
	setup_mem_handle = kobject_create(KOBJ_TYPE_PMA, (unsigned long)&args);
	assert(setup_mem_handle > 0);

	handle = kobject_create_port();
	assert(handle > 0);

	hdesc[0].handle = handle;
	hdesc[0].right = KR_R;
	hdesc[1].handle = setup_mem_handle;
	hdesc[1].right = KR_RWCM;

	/*
	 * the setup_mem_handle will pass to the chiyou service
	 * then chiyou service can map it to its address space.
	 */
	chiyou_proc = load_ramdisk_process("chiyou.srv", hdesc, 2, TASK_FLAGS_SRV);
	if (!chiyou_proc)
		return -ENOMEM;

	kobject_ctl(chiyou_proc->proc_handle, KOBJ_PROCESS_GRANT_RIGHT,
			PROC_FLAGS_VMCTL | PROC_FLAGS_HWCTL);
	chiyou_handle = handle;

	return kobject_ctl(chiyou_proc->proc_handle, KOBJ_PROCESS_WAKEUP, 0);
}

static int load_fuxi_service(void)
{
	struct handle_desc hdesc[1];
	int handle;

	/*
	 * create the endpoint for fuxi service, that it
	 * can commuicate with other process, this endpoint
	 * will grant to fuxi service
	 */
	handle = kobject_create_port();
	if (handle <= 0)
		return handle;

	hdesc[0].handle = handle;
	hdesc[0].right = KR_R;

	fuxi_proc = load_ramdisk_process("fuxi.srv", hdesc, 1, TASK_FLAGS_SRV);
	if (fuxi_proc == NULL)
		return -ENOMEM;

	fuxi_handle = handle;

	return start_and_wait_process(fuxi_proc);
}

static int load_rootfs_driver(void)
{
	char *path = NULL;
	int ret;

	ret = bootarg_parse_string("rootfs", &path);
	path = ret ? rootfs_default : path;
	rootfs_proc = load_ramdisk_process(path, NULL, 0, TASK_FLAGS_DRV);
	if (rootfs_proc == NULL)
		return -ENOENT;

	return kobject_ctl(rootfs_proc->proc_handle,
			KOBJ_PROCESS_GRANT_RIGHT, PROC_FLAGS_VMCTL);
}

int main(int argc, char **argv)
{
	int i;

	printf("\n\nPanGu service start...\n\n");

	for (i = 0; i < argc; i++)
		get_boot_opt(argv[i]);

	if (bootdata == NULL) {
		pr_err("bootdata not found\n");
		return -EINVAL;
	}

	if (bootdata->magic != BOOTDATA_MAGIC) {
		pr_err("bootdata magic wrong\n");
		return -EINVAL;
	}

	heap_base = bootdata->heap_start;
	heap_end = bootdata->heap_end;
	dump_boot_info();

	assert(!kmalloc_init(heap_base, heap_end));

	ramdisk_init(bootdata->ramdisk_start, bootdata->ramdisk_end);
	of_init(bootdata->dtb_start, bootdata->dtb_end);
	procinfo_init(bootdata->max_proc, bootdata->uproc_info_handle,
			bootdata->ktask_stat_handle);
	self_init(bootdata->vmap_start, bootdata->vmap_end);

	/*
	 * create the epoll fd for pangu, pangu will use this handle
	 * to handle all the request from other process.
	 */
	proc_epfd = epoll_create(0);
	if (proc_epfd < 0) {
		pr_err("can not create epoll fd\n");
		exit(-ENOENT);
	}

	assert(!load_fuxi_service());
	assert(!load_nvwa_service());
	assert(!load_chiyou_service());
	assert(!load_rootfs_driver());

	/*
	 * setup the rootfs handle, so pangu can use fopen
	 * related LIBC api
	 */
	libc_set_rootfs_handle(fuxi_handle);

	pangu_main();

	return -1;
}
