/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <minos/types.h>
#include <minos/debug.h>
#include <minos/kobject.h>
#include <minos/kmalloc.h>

#include <pangu/of.h>
#include <pangu/resource.h>

int request_device_resource(const char *name, struct resource **res_ret)
{
	struct resource *head = NULL, *res;
	struct pma_create_arg args;

	/*
	 * just for test. need to parse the device tree to
	 * get the device's information and create all the
	 * resource which this device need. here just prepare
	 * the virtio-blk for test.
	 */
	res = kzalloc(sizeof(struct resource));
	res->type = RES_TYPE_MMIO;
	res->base = 0x1c130000;
	res->end = 0x1c131000;
	args.cnt = (res->end - res->base) >> PAGE_SHIFT;
	args.type = PMA_TYPE_MMIO;
	args.start = res->base;
	args.end = res->end;
	res->handle = kobject_create(KOBJ_TYPE_PMA,
			KR_RWCMSG, KR_G, (unsigned long)&args);
	pr_info("mmio handle %d\n", res->handle);
	res->next = head;
	head = res;

	res = kzalloc(sizeof(struct resource));
	res->type = RES_TYPE_IRQ;
	res->base = 74;
	res->end = 74;
	res->handle = kobject_create(KOBJ_TYPE_IRQ,
			RES_DEFAULT_RIGHT | KOBJ_RIGHT_GRANT,
			KOBJ_RIGHT_RW, 74);
	res->next = head;
	head = res;

	*res_ret = head;

	return 0;
}

void release_resource(struct resource *head)
{

}
