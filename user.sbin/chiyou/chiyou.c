/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <misc.h>
#include <errno.h>
#include <minos/kobject.h>
#include <minos/proto.h>
#include <minos/types.h>
#include <minos/debug.h>

#include "of.h"

#define BUF_SIZE 256

enum {
	RES_TYPE_MMIO,
	RES_TYPE_IRQ,
	RES_TYPE_GPIO,
	RES_TYPE_DMA_CHANNEL,
	RES_TYPE_IOMMU_SID,
	RES_TYPE_MAX,
};

struct resource {
	uint8_t type;
	uint8_t index;
	int handle;
	unsigned long base;
	unsigned long end;
	struct list_head list;
};

static int pmem_handle;
static int chiyou_handle;

static void *dtb_base;
static char buf[BUF_SIZE];

static int create_mmio_handle(unsigned long base, unsigned long size)
{
	struct pma_create_arg args;

	size = PAGE_BALIGN(size);
	args.cnt = size >> PAGE_SHIFT;
	args.type = PMA_TYPE_MMIO;
	args.start = base;
	args.end = base + size;

	return kobject_create(KOBJ_TYPE_PMA,
			KR_RWCM, KR_RWCM, (unsigned long)&args);
}

static int create_irq_handle(uint32_t irq, unsigned long flags)
{
	return kobject_create(KOBJ_TYPE_IRQ, KR_RW, 0, irq);
}

static int get_device_node(const char *name,
		uint32_t key, struct device_node **dnode)
{
	struct device_node *__dnode;
	char *comp[2] = {buf, NULL};

	__dnode = of_find_node_by_compatible(of_root_node, comp);
	if (!__dnode) {
		pr_err("can not find device [%s]\n", buf);
		return -ENOENT;
	}
	
	// if (__dnode->key != key)
	//	return -EACCES;

	*dnode = __dnode;

	return 0;
}

static int handle_get_mmio(struct device_node *dnode, int index)
{
	struct resource *res;
	uint64_t addr, size;
	int ret, handle;

	list_for_each_entry(res, &dnode->resource_list, list) {
		if (res->type != RES_TYPE_MMIO)
			continue;

		if (res->index == index)
			return res->handle;
	}

	/*
	 * get the mmio range from the dtb.
	 */
	ret = of_translate_address_index(dnode, &addr, &size, index);
	if (ret)
		return ret;

	handle = create_mmio_handle(addr, size);
	if (handle <= 0)
		return -ENOMEM;

	res = zalloc(sizeof(struct resource));
	if (!res) {
		kobject_close(handle);
		return -ENOMEM;
	}

	res->type = RES_TYPE_MMIO;
	res->base = addr;
	res->end = addr + size;
	res->handle = handle;
	res->index = index;
	list_add_tail(&dnode->resource_list, &res->list);

	return handle;
}

static int handle_get_irq(struct device_node *dnode, int index)
{
	struct resource *res;
	unsigned long flags;
	uint32_t irq;
	int ret, handle;

	list_for_each_entry(res, &dnode->resource_list, list) {
		if (res->type != RES_TYPE_IRQ)
			continue;

		if (res->index == index)
			return res->handle;
	}

	ret = of_get_device_irq_index(dnode, &irq, &flags, index);
	if (ret)
		return ret;

	handle = create_irq_handle(irq, flags);
	if (handle <= 0)
		return -ENOENT;

	res = zalloc(sizeof(struct resource));
	if (!res) {
		kobject_close(handle);
		return -ENOMEM;
	}

	res->type = RES_TYPE_IRQ;
	res->base = irq;
	res->end = irq;
	res->handle = handle;
	res->index = index;
	list_add_tail(&dnode->resource_list, &res->list);

	return handle;


	return 0;
}

static int handle_get_dma_channel(struct device_node *dnode, int index)
{
	return 0;
}

static int handle_get_iommu_sid(struct device_node *dnode, int index)
{
	return 0;
}

static int do_handle_chiyou_event(struct proto *proto, char *buf)
{
	struct proto_devinfo *dinfo = &proto->devinfo;
	struct device_node *dnode;
	long ret;

	ret = get_device_node(buf, dinfo->key, &dnode);
	if (ret)
		return ret;

	switch (proto->proto_id) {
	case PROTO_GET_MMIO:
		ret = handle_get_mmio(dnode, dinfo->index);
		break;
	case PROTO_GET_IRQ:
		ret = handle_get_irq(dnode, dinfo->index);
		break;
	case PROTO_GET_DMA_CHANEL:
		ret = handle_get_dma_channel(dnode, dinfo->index);
		break;
	case PROTO_GET_IOMMU_SID:
		ret = handle_get_iommu_sid(dnode, dinfo->index);
		break;
	default:
		ret = -ENOSYS;
		pr_err("unknow chiyou event %d\n", proto->proto_id);
		break;
	}

	return ret;
}

static int handle_chiyou_event(int loop)
{
	struct proto proto;
	int ret;

	for (;;) {
		ret = kobject_read_proto_with_string(chiyou_handle,
				&proto, buf, BUF_SIZE, -1);
		if (ret) {
			pr_err("read proto fail %d\n", ret);
			continue;
		}

		if (proto.proto_id == PROTO_ROOTFS_READY) {
			kobject_reply_errcode(chiyou_handle, proto.token, 0);
			if (!loop)
				break;
		} else {
			ret = do_handle_chiyou_event(&proto, buf);
			if (ret <= 0) {
				pr_err("handle chiyou event fail %d %s %d %d\n",
						ret, buf, proto.proto_id,
						proto.devinfo.index);
			}

			kobject_reply_handle(chiyou_handle, proto.token, ret, KR_RWCM);
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret, handles[2];

	ret = get_handles(argc, argv, handles, 2);
	if (ret != 2) {
		pr_err("get handles from argv fail\n");
		exit(-ENOENT);
	}

	chiyou_handle = handles[0];
	pmem_handle = handles[1];

	if (chiyou_handle <= 0 || pmem_handle <= 0) {
		pr_err("invalid handle for chiyou %d %d\n",
					chiyou_handle, pmem_handle);
		exit(-EINVAL);
	}

	dtb_base = kobject_mmap(pmem_handle);
	if (dtb_base == (void *)-1) {
		pr_err("mmap dtb address fail\n");
		exit(-ENOMEM);
	}

	if (of_init(dtb_base))
		exit(-EIO);

	/*
	 * since the rootfs may not ready now, and the rootfs driver
	 * will also get the information from the chiyou service. need
	 * wait here, and get the ready signal from rootfs, then loading
	 * the drivers from the rootfs.
	 */
	ret = handle_chiyou_event(0);
	if (ret)
		exit(ret);

	/*
	 * then try to load all the request driver for each
	 * device.
	 */
	// load_drivers();

	handle_chiyou_event(1);

	return 0;
}
