/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/epoll.h>

#include <minos/debug.h>
#include <minos/kmalloc.h>
#include <minos/kobject.h>
#include <minos/proto.h>

#include <uapi/bootdata.h>

#include <pangu/proc.h>
#include <pangu/bootarg.h>

static struct bootdata *bootdata;

extern void ramdisk_init(unsigned long base, unsigned long end);
extern void of_init(unsigned long base, unsigned long end);
extern void pangu_main(void);

unsigned long heap_base, heap_end;

static char *rootfs_default = "rootfs.drv";
struct process *rootfs_proc;

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

static int load_fuxi_service(void)
{
	struct process *proc;
	struct proto proto;
	int ret;

	/*
	 * create the endpoint for fuxi service, that it
	 * can commuicate with other process, this endpoint
	 * will grant to fuxi service
	 */
	fuxi_handle = kobject_create_port(KR_RWCG, KR_WG);
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

	/*
	 * start the fuxi service and wait it finish startup
	 */
	pr_info("Start Fuxi service and waitting ...\n");
	kobject_ctl(proc->proc_handle, KOBJ_PROCESS_WAKEUP, 0);
	kobject_read_simple(proc->proc_handle,
			&proto, sizeof(struct proto), -1);

	if (proto.proto_id != PROTO_IAMOK)
		return -EPROTO;

	kobject_reply_errcode(proc->proc_handle, proto.token, 0);

	return 0;
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

	rootfs_proc = load_ramdisk_process(drv_name, 0, NULL,
			TASK_FLAGS_DRV | TASK_FLAGS_DEDICATED_HEAP, res);
	if (rootfs_proc == NULL)
		goto err_release_resource;

	return 0;

err_release_resource:
	release_resource(res);
out:
	kfree(buf);
	return ret;
}

int main(int argc, char **argv)
{
	int i, ret;

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

	ret = load_fuxi_service();
	if (ret)
		exit(ret);

	/*
	 * load the rootfs driver process, the rootfs driver
	 * need to store in the ramdisk. rootfs driver process
	 * will handle the request of the filesystem.
	 */
	ret = load_rootfs_driver();
	if (ret)
		exit(ret);

	pangu_main();

	return -1;
}
