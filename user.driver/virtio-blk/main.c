/*
 * Copyright (C) 2020 Min Le (lemin9538@gmail.com)
 */

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <minos/debug.h>
#include <minos/list.h>

#include <drv/drv.h>
#include <vfs/vfs.h>
#include "virtio.h"

static int irq_handle, mmio_handle;

/*
 * mmio@4,5,6 irq@1,2,3
 */
int main(int argc, char **argv)
{
	int ret;
	void *mmio;

	ret = get_mmio_handles(argc, argv, &mmio_handle, 1);
	if (ret <= 0) {
		pr_err("no mmio handle found\n");
		exit(-ENOENT);
	}

	ret = get_irq_handles(argc, argv, &irq_handle, 1);
	if (ret <= 0) {
		pr_err("no irq handle found\n");
		exit(-ENOENT);
	}

	if (irq_handle < 0 || mmio_handle < 0) {
		pr_err("virtio-blk: wrong irq or mmio information\n");
		return -EINVAL;
	}

	mmio = request_mmio_by_handle(mmio_handle);
	if (mmio == (void *)-1)
		return -EACCES;

	ret = request_irq_by_handle(irq_handle);
	if (ret) {
		pr_err("failed to request virtio block irq\n");
		return -EIO;
	}

	vfs_init();

	virtio_dev_init((unsigned long)mmio, irq_handle);

	while (1) {

	}
}
