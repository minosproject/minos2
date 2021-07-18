/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <minos/debug.h>
#include <minos/kmalloc.h>

#include <uapi/bootdata.h>

#include <pangu/proc.h>
#include <pangu/bootarg.h>

static struct bootdata *bootdata;
extern void ramdisk_init(unsigned long base, unsigned long end);
extern void of_init(unsigned long base, unsigned long end);

unsigned long heap_base, heap_end;

static char *rootfs_default = "rootfs.drv";

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

static int pangu_loop(void)
{
	while (1) {

	}

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

	ret = load_ramdisk_process(drv_name, 0, NULL,
			TASK_FLAGS_DRV | TASK_FLAGS_DEDICATED_HEAP, res);
	if (ret)
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
	 * load the rootfs driver process, the rootfs driver
	 * need to store in the ramdisk. rootfs driver process
	 * will handle the request of the filesystem.
	 */
	ret = load_rootfs_driver();
	if (ret)
		exit(-EIO);

	/*
	 * every thing is down, wakeup all the process created
	 * by PanGu.
	 */
	wakeup_all_process();

	return  pangu_loop();
}
