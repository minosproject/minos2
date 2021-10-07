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
#include <minos/device.h>

#include "virtio.h"

static int irq_handle, mmio_handle;

int main(int argc, char **argv)
{
	int ret;
	void *mmio;

	mmio_handle = get_device_mmio_handle("virtio,mmio", 0);
	irq_handle = get_device_irq_handle("virtio,mmio", 0);
	if (irq_handle <= 0 || mmio_handle <= 0) {
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

	return virtio_dev_init((unsigned long)mmio, irq_handle);
}
