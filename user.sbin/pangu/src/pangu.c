/*
 * Copyright (C) 2021 Min Le (lemin9538@163.com)
 * Copyright (c) 2021 上海网返科技
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
#include <minos/kmalloc.h>
#include <minos/proto.h>
#include <minos/libc.h>

#include <uapi/bootdata.h>

#include <pangu/proc.h>
#include <pangu/request.h>
#include <pangu/bootarg.h>

int proc_epfd;
int fuxi_handle;
int nvwa_handle;

struct process *rootfs_proc;
struct process *nvwa_proc;

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
	struct process *proc;
	int ret;
	
	nvwa_handle = kobject_create_endpoint(KR_RWG, KR_WG, 0);
	if (nvwa_handle <= 0)
		return nvwa_handle;

	proc = load_ramdisk_process("nvwa.srv", 0, NULL, TASK_FLAGS_SRV |
			TASK_FLAGS_DEDICATED_HEAP, NULL);
	if (proc == NULL)
		return -ENOMEM;

	ret = grant(proc->proc_handle, nvwa_handle, KR_R);
	if (ret <= 0)
		return ret;

	ret = kobject_ctl(proc->proc_handle, KOBJ_PROCESS_SETUP_REG0, ret);
	if (ret)
		return ret;

	nvwa_proc = proc;

	return start_and_wait_process(proc);
}

static int load_fuxi_service(void)
{
	struct process *proc;
	int ret;

	/*
	 * create the endpoint for fuxi service, that it
	 * can commuicate with other process, this endpoint
	 * will grant to fuxi service
	 */
	fuxi_handle = kobject_create_port(KR_RWG, KR_WG);
	if (fuxi_handle <= 0)
		return fuxi_handle;

	proc = load_ramdisk_process("fuxi.srv", 0, NULL, TASK_FLAGS_SRV, NULL);
	if (proc == NULL)
		return -ENOMEM;

	/*
	 * fuxi service will be the second process in the process
	 * list after self_init()
	 */
	ret = grant(proc->proc_handle, fuxi_handle, KR_R);
	if (ret <= 0)
		return ret;

	ret = kobject_ctl(proc->proc_handle, KOBJ_PROCESS_SETUP_REG0, ret);
	if (ret)
		return ret;

	return start_and_wait_process(proc);
}

static int load_rootfs_driver(void)
{
	char *buf, *drv_name, *dev_name;
	char *path = NULL;
	struct resource *res;
	int ret;

	ret = bootarg_parse_string("rootfs", &path);
	if (ret)
		path = rootfs_default;

	buf = kmalloc(strlen(path) + 1);
	if (!buf)
		return -ENOMEM;

	/*
	 * rootfs cmdline need to be as below format
	 *   rootfs="virtioblk.drv@virtio_block"
	 */
	strcpy(buf, path);
	path = strchr(buf, '@');
	if (!path) {
		ret = -ENOENT;
		goto out;
	}

	*path = 0;
	drv_name = buf;
	dev_name = path + 1;

	ret = request_device_resource(dev_name, &res);
	if (ret)
		goto out;

	rootfs_proc = load_ramdisk_process(drv_name, 0, NULL, TASK_FLAGS_DRV, res);
	if (rootfs_proc == NULL) {
		ret = -ENOENT;
		goto err_release_resource;
	}

	return 0;

err_release_resource:
	release_resource(res);
out:
	kfree(buf);
	return ret;
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
	assert(!load_rootfs_driver());

	/*
	 * setup the rootfs handle, so pangu can use fopen
	 * related LIBC api
	 */
	libc_set_rootfs_handle(fuxi_handle);

	pangu_main();

	return -1;
}
