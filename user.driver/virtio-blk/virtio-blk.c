/**
 * Block device driver based on virtio.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

#include <minos/debug.h>
#include <minos/list.h>
#include <minos/types.h>
#include <minos/sched.h>
#include <minos/kobject.h>
#include <minos/map.h>
#include <minos/proto.h>
#include <minos/service.h>
#include <minos/device.h>

#include <lwext4/ext4_blkdev.h>

#include "virtio.h"

#define VFS_MAX_EVENTS 16

struct virtio_cap blk_caps[] = {
	{ "VIRTIO_BLK_F_SIZE_MAX", 1, false,
	  "Maximum size of any single segment is in size_max." },
	{ "VIRTIO_BLK_F_SEG_MAX", 2, false,
	  "Maximum number of segments in a request is in seg_max." },
	{ "VIRTIO_BLK_F_GEOMETRY", 4, false,
	  "Disk-style geometry specified in geometry." },
	{ "VIRTIO_BLK_F_RO", 5, false, "Device is read-only." },
	{ "VIRTIO_BLK_F_BLK_SIZE", 6, false,
	  "Block size of disk is in blk_size." },
	{ "VIRTIO_BLK_F_FLUSH", 9, false, "Cache flush command support." },
	{ "VIRTIO_BLK_F_TOPOLOGY", 10, false,
	  "Device exports information on optimal I/O alignment." },
	{ "VIRTIO_BLK_F_CONFIG_WCE", 11, false,
	  "Device can toggle its cache between writeback and "
	  "writethrough modes." },
	VIRTIO_INDP_CAPS
};

#define get_vblkreq(req) container_of(req, struct virtio_blk_req, blkreq)

static struct virtio_blk vblk_dev;

struct virtio_blk {
	virtio_regs *regs;
	struct virtio_blk_config config;
	struct virtqueue *virtq;
	uint32_t intid;
	uint64_t sector_cnt;
};
#define get_vblkdev(dev) container_of(dev, struct virtio_blk, blkdev)

#define HI32(u64) ((uint32_t)((0xFFFFFFFF00000000ULL & (u64)) >> 32))
#define LO32(u64) ((uint32_t)(0x00000000FFFFFFFFULL & (u64)))

static void virtio_blk_handle_used(struct virtio_blk *dev, uint32_t usedidx)
{
	struct virtqueue *virtq = dev->virtq;
	uint32_t desc1, desc2, desc3;
	struct virtio_blk_req *req;

	desc1 = virtq->used->ring[usedidx].id;
	if (!(virtq->desc[desc1].flags & VIRTQ_DESC_F_NEXT))
		goto bad_desc;
	desc2 = virtq->desc[desc1].next;
	if (!(virtq->desc[desc2].flags & VIRTQ_DESC_F_NEXT))
		goto bad_desc;
	desc3 = virtq->desc[desc2].next;
	if (virtq->desc[desc1].len != VIRTIO_BLK_REQ_HEADER_SIZE ||
	    virtq->desc[desc2].len != VIRTIO_BLK_SECTOR_SIZE ||
	    virtq->desc[desc3].len != VIRTIO_BLK_REQ_FOOTER_SIZE)
		goto bad_desc;

	req = virtq->desc_virt[desc1];

	virtq_free_desc(virtq, desc1);
	virtq_free_desc(virtq, desc2);
	virtq_free_desc(virtq, desc3);

	switch (req->status) {
	case VIRTIO_BLK_S_OK:
		req->blkreq.status = BLKREQ_OK;
		break;
	case VIRTIO_BLK_S_IOERR:
		req->blkreq.status = BLKREQ_ERR;
		break;
	default:
		puts("Unhandled status in virtio_blk irq\n");
		break;
	}

	return;

bad_desc:
	pr_err("virtio-blk received malformed descriptors\n");
	return;
}

static void virtio_blk_isr(void)
{
	int i, len;
	struct virtio_blk *dev = &vblk_dev;

	len = dev->virtq->len;
	WRITE32(dev->regs->InterruptACK, READ32(dev->regs->InterruptStatus));

	for (i = dev->virtq->seen_used; i != (dev->virtq->used->idx % len);
	     i = wrap(i + 1, len)) {
		virtio_blk_handle_used(dev, i);
	}

	dev->virtq->seen_used = dev->virtq->used->idx % len;
}

static int virtio_blk_poll(struct virtio_blk *blk, struct blkreq *req)
{
	int ret;

	ret = kobject_read(blk->intid, NULL, 0, NULL, NULL, 0, NULL, -1);
	if (ret != 0) {
		pr_err("get wrong virtio irq state %d\n", ret);
		return ret;
	}

	virtio_blk_isr();

	kobject_write(blk->intid, NULL, 0, NULL, 0, 0);

	return 0;
}

static void virtio_blk_send(struct virtio_blk *blk, struct virtio_blk_req *hdr)
{
	blk->virtq->avail->ring[blk->virtq->avail->idx % blk->virtq->len] =
	        hdr->descriptor;
	blk->virtq->avail->idx += 1;
	mb();

	WRITE32(blk->regs->QueueNotify, 0);
}

#if 0
static int virtio_blk_status(struct virtio_blk *blkdev)
{
	pr_info("    Status=0x%x\n", READ32(blkdev->regs->Status));
	pr_info("    DeviceID=0x%x\n", READ32(blkdev->regs->DeviceID));
	pr_info("    VendorID=0x%x\n", READ32(blkdev->regs->VendorID));
	pr_info("    InterruptStatus=0x%x\n",
	       READ32(blkdev->regs->InterruptStatus));
	pr_info("    MagicValue=0x%x\n", READ32(blkdev->regs->MagicValue));
	pr_info("  Queue 0:\n");
	pr_info("    avail.idx = %u\n", blkdev->virtq->avail->idx);
	pr_info("    used.idx = %u\n", blkdev->virtq->used->idx);
	WRITE32(blkdev->regs->QueueSel, 0);
	mb();
	pr_info("    ready = 0x%x\n", READ32(blkdev->regs->QueueReady));
	virtq_show(blkdev->virtq);
	return 0;
}
#endif

static struct blkreq *virtio_blk_alloc(struct virtio_blk *dev)
{
	struct virtio_blk_req *vblkreq;
	
	vblkreq = zalloc(sizeof(struct virtio_blk_req));
	if (!vblkreq)
		return NULL;

	return &vblkreq->blkreq;
}

static void virtio_blk_free(struct virtio_blk *blk, struct blkreq *req)
{
	struct virtio_blk_req *vblkreq = get_vblkreq(req);
	free(vblkreq);
}

static int virtio_blk_submit(struct virtio_blk *blk, struct blkreq *req)
{
	struct virtio_blk_req *hdr = get_vblkreq(req);
	uint32_t d1, d2, d3, datamode = 0;

	if (req->type == BLKREQ_READ) {
		hdr->type = VIRTIO_BLK_T_IN;
		datamode = VIRTQ_DESC_F_WRITE; /* mark page writeable */
	} else {
		hdr->type = VIRTIO_BLK_T_OUT;
	}
	hdr->sector = req->blkidx;

	d1 = virtq_alloc_desc(blk->virtq, hdr);
	hdr->descriptor = d1;
	blk->virtq->desc[d1].len = VIRTIO_BLK_REQ_HEADER_SIZE;
	blk->virtq->desc[d1].flags = VIRTQ_DESC_F_NEXT;

	d2 = virtq_alloc_desc(blk->virtq, req->buf);
	blk->virtq->desc[d2].len = VIRTIO_BLK_SECTOR_SIZE;
	blk->virtq->desc[d2].flags = datamode | VIRTQ_DESC_F_NEXT;

	d3 = virtq_alloc_desc(blk->virtq,
	                      (void *)hdr + VIRTIO_BLK_REQ_HEADER_SIZE);
	blk->virtq->desc[d3].len = VIRTIO_BLK_REQ_FOOTER_SIZE;
	blk->virtq->desc[d3].flags = VIRTQ_DESC_F_WRITE;

	blk->virtq->desc[d1].next = d2;
	blk->virtq->desc[d2].next = d3;

	virtio_blk_send(blk, hdr);

	return 0;
}

#define __raw_read8(a)	(*(volatile uint8_t *)(a))

static void get_config(void *base, unsigned offset, void *buf, unsigned len)
{
	uint8_t *ptr = buf;
	int i;

	for (i = 0; i < len; i++)
		ptr[i] = __raw_read8(base + offset + i);
}

static int blkreq_wait_all(struct virtio_blk *bdev, struct list_head *breq_list)
{
	struct blkreq *breq;

	list_for_each_entry(breq, breq_list, list) {
		if (breq->status != 0)
			continue;

		while (breq->status == 0)
			virtio_blk_poll(bdev, breq);
	}

	list_for_each_entry(breq, breq_list, list) {
		if (breq->status == BLKREQ_ERR)
			return BLKREQ_ERR;
	}

	return BLKREQ_OK;
}

int submit_blkreq_one(struct virtio_blk *bdev, struct blkreq *breq)
{
	int ret;

	ret = virtio_blk_submit(bdev, breq);
	if (ret)
		return ret;

	while (breq->status == 0)
		yield();

	return (breq->status == BLKREQ_ERR);
}

int submit_blkreq_many(struct virtio_blk *vdev, struct list_head *breq_list)
{
	struct blkreq *breq;
	int ret, status;

	if (is_list_empty(breq_list)) {
		pr_err("block request list is empty\n");
		return -EINVAL;
	}

	list_for_each_entry(breq, breq_list, list) {
		ret = virtio_blk_submit(vdev, breq);
		if (ret) {
			ret = -EIO;
			break;
		}
	}

	status = blkreq_wait_all(vdev, breq_list);
	if (status != BLKREQ_OK)
		ret = -EIO;

	return ret;
}

static int request_virtio_blkdev_sectors(struct virtio_blk *vdev, void *buf,
		uint64_t start, uint32_t cnt, int op)
{
	LIST_HEAD(blkreq_list);
	struct blkreq *breq, *next;
	int i, ret = 0, status;

	for (i = 0; i < cnt; i++) {
		breq = virtio_blk_alloc(vdev);
		if (!breq) {
			ret = -ENOMEM;
			goto out;
		}

		breq->blkidx = start + i;
		breq->type = op;
		breq->buf = buf + i * VIRTIO_BLK_SECTOR_SIZE;
		breq->size = VIRTIO_BLK_SECTOR_SIZE;
		ret = virtio_blk_submit(vdev, breq);
		if (ret) {
			virtio_blk_free(vdev, breq);
			ret = -EIO;
			break;
		}
		list_add_tail(&blkreq_list, &breq->list);
	}

	status = blkreq_wait_all(vdev, &blkreq_list);
	if (status != BLKREQ_OK)
		ret = -EIO;

out:
	list_for_each_entry_safe(breq, next, &blkreq_list, list) {
		list_del(&breq->list);
		virtio_blk_free(vdev, breq);
	}

	return ret;
}

static int virtio_ext4_iface_bread(struct ext4_blockdev *bdev, void *buf,
		uint64_t blk_id, uint32_t blk_cnt)
{
	struct virtio_blk *vdev = bdev->bdif->p_user;

	return request_virtio_blkdev_sectors(vdev, buf, blk_id,
			blk_cnt, BLKREQ_READ);
}

static int virtio_ext4_iface_bwrite(struct ext4_blockdev *bdev, const void *buf,
		uint64_t blk_id, uint32_t blk_cnt)
{
	struct virtio_blk *vdev = bdev->bdif->p_user;

	return request_virtio_blkdev_sectors(vdev, (void *)buf,
			blk_id, blk_cnt, BLKREQ_READ);
}

static int virtio_ext4_iface_open(struct ext4_blockdev *bdev)
{
	bdev->bdif->ph_bcnt = bdev->part_size / bdev->bdif->ph_bsize;

	return 0;
}

static int virtio_ext4_iface_close(struct ext4_blockdev *bdev)
{
	return 0;
}

static uint8_t ext4_phbuf[PAGE_SIZE];
static struct ext4_blockdev_iface virtio_ext4_iface = {
	.open	= virtio_ext4_iface_open,
	.bread	= virtio_ext4_iface_bread,
	.bwrite = virtio_ext4_iface_bwrite,
	.close	= virtio_ext4_iface_close,
	.lock	= NULL,
	.unlock = NULL,
	.ph_bsize = VIRTIO_BLK_SECTOR_SIZE,
	.p_user = &vblk_dev,
	.ph_bbuf = ext4_phbuf,
};

static int run_virtio_block_ext4_server(void)
{
	static struct ext4_blockdev bdev;
	struct virtio_blk *vdev = &vblk_dev;

	memset(&bdev, 0, sizeof(struct ext4_blockdev));
	bdev.bdif = &virtio_ext4_iface;
	bdev.part_offset = 0;
	bdev.part_size = vdev->sector_cnt * VIRTIO_BLK_SECTOR_SIZE;

	return run_ext4_file_server(&bdev);
}

int virtio_blk_init(virtio_regs *regs, uint32_t intid)
{
	struct virtio_blk *vdev;
	struct virtqueue *virtq;
	uint32_t genbefore, genafter;

	vdev = &vblk_dev;
	memset(vdev, 0, sizeof(struct virtio_blk));

	virtio_check_capabilities(regs, blk_caps,
			ARRAY_SIZE(blk_caps), "virtio-blk");

	WRITE32(regs->Status, READ32(regs->Status) | VIRTIO_STATUS_FEATURES_OK);
	mb();

	if (!(regs->Status & VIRTIO_STATUS_FEATURES_OK)) {
		puts("error: virtio-blk did not accept our features\n");
		return -1;
	}

	virtq = virtq_create(regs, 32);
	virtq_add_to_device(regs, virtq, 0);

	vdev->regs = regs;
	vdev->virtq = virtq;
	vdev->intid = intid;

	/* capacity is 64 bit, configuration reg read is not atomic */
	do {
		genbefore = READ32(vdev->regs->ConfigGeneration);
		get_config((void *)regs, 0x100, &vdev->config,
				sizeof(struct virtio_blk_config));
		genafter = READ32(vdev->regs->ConfigGeneration);
	} while (genbefore != genafter);

	vdev->sector_cnt = vdev->config.capacity;
	pr_info("vd0 capacity : %ldMB\n", vdev->config.capacity * VIRTIO_BLK_SECTOR_SIZE / 1024 / 1024);

	WRITE32(regs->Status, READ32(regs->Status) | VIRTIO_STATUS_DRIVER_OK);
	mb();

	return run_virtio_block_ext4_server();
}
