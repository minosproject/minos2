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

#include <uapi/bootdata.h>

#include <pangu/kmalloc.h>
#include <pangu/proc.h>
#include <pangu/request.h>
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

static LIST_HEAD(request_entry_list);
static struct bootdata *bootdata;
static char *rootfs_default = "rootfs.drv";

#define MAX_EVENT 16

static struct request_entry *alloc_request_entry(int type, void *data)
{
	struct request_entry *re;

	re = kzalloc(sizeof(struct request_entry));
	if (!re) {
		pr_err("register request entry failed %d\n", type);
		return re;
	}

	re->type = type;
	re->data = data;
	list_add_tail(&request_entry_list, &re->list);

	return re;
}

int register_request_entry(int type, int handle, void *data)
{
	struct request_entry *re;
	struct epoll_event event;

	re = alloc_request_entry(type, data);
	if (!re)
		return -ENOMEM;

	event.events = EPOLLIN | EPOLLKERNEL;
	event.data.ptr = re;

	return epoll_ctl(proc_epfd, EPOLL_CTL_ADD, handle, &event);
}

static void handle_event(struct epoll_event *event)
{
	struct request_entry *re = event->data.ptr;

	if (!re) {
		pr_err("invalid event receive\n");
		return;
	}

	switch (re->type) {
	case REQUEST_TYPE_PROCESS:
		handle_process_request(event, re);
		break;
	case REQUEST_TYPE_PROCFS:
		handle_procfs_request(event, re);
		break;
	default:
		pr_err("invalid request type %d\n", re->type);
		break;
	}
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
	procfs_init();
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
}

static int start_and_wait_process(struct process *proc)
{
	struct proto proto;
	int ret;

	/*
	 * start the fuxi service and wait it finish startup
	 */
	pr_info("Start %s and waitting ...\n", proc->name);
	kobject_ctl(proc->proc_handle, KOBJ_PROCESS_WAKEUP, 0);

	for (;;) {
		ret = kobject_read_simple(proc->proc_handle,
			&proto, sizeof(struct proto), -1);
		if (ret == 0)
			break;

		if (ret != -EAGAIN)
			break;
	}

	if (ret) {
		pr_info("Get response from %s fail %d\n", proc->name, ret);
		return ret;
	}

	pr_info("Get response from %s service %d\n", proc->name, proto.proto_id);
	if (proto.proto_id != PROTO_IAMOK)
		return -EPROTO;

	kobject_reply_errcode(proc->proc_handle, 0, 0);

	return 0;
}

static int load_nvwa_service(void)
{
	struct handle_desc hdesc[1];
	
	nvwa_handle = kobject_create_endpoint(KR_RW, KR_W, 0);
	if (nvwa_handle <= 0)
		return nvwa_handle;

	hdesc[0].handle = nvwa_handle;
	hdesc[0].right = KR_R;
	nvwa_proc = load_ramdisk_process("nvwa.srv", hdesc, 1, TASK_FLAGS_DRV);
	if (nvwa_proc == NULL)
		return -ENOMEM;

	return start_and_wait_process(nvwa_proc);
}

static int load_chiyou_service(void)
{
	unsigned long pbase, pend;
	struct pma_create_arg args;
	struct handle_desc hdesc[2];
	int handle;

	/*
	 * chiyou service will handle the dtb or setup
	 * data, each driver or service will get information
	 * from it.
	 */
	pbase = kobject_ctl(0, KOBJ_PROCESS_VA2PA, bootdata->dtb_start);
	pend = kobject_ctl(0, KOBJ_PROCESS_VA2PA, bootdata->dtb_end);
	assert(pend > pbase);

	args.cnt = 0;
	args.type = PMA_TYPE_PMEM;
	args.consequent = 0;
	args.start = pbase;
	args.end = pend;
	setup_mem_handle = kobject_create(KOBJ_TYPE_PMA, KR_RWCM,
			KR_RW, (unsigned long)&args);
	assert(setup_mem_handle > 0);

	handle = kobject_create_port(KR_RW, KR_W);
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
	if (chiyou_proc)
		return -ENOMEM;

	chiyou_handle = handle;

	return start_and_wait_process(chiyou_proc);
}

static int load_fuxi_service(void)
{
	int ret, handle;

	/*
	 * create the endpoint for fuxi service, that it
	 * can commuicate with other process, this endpoint
	 * will grant to fuxi service
	 */
	handle = kobject_create_port(KR_RW, KR_W);
	if (handle <= 0)
		return handle;

	fuxi_proc = load_ramdisk_process("fuxi.srv", NULL, 0, TASK_FLAGS_SRV);
	if (fuxi_proc == NULL)
		return -ENOMEM;

	ret = grant(fuxi_proc->proc_handle, handle, KR_R);
	if (ret <= 0)
		return ret;

	ret = kobject_ctl(fuxi_proc->proc_handle, KOBJ_PROCESS_SETUP_REG0, ret);
	if (ret)
		return ret;

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
			KOBJ_PROCESS_GRANT_RIGHT, KOBJ_RIGHT_VMCTL);
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
