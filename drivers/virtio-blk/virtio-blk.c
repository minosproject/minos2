/**
 * Block device driver based on virtio.
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <minos/kmalloc.h>
#include <minos/debug.h>
#include <minos/list.h>
#include <minos/types.h>
#include <minos/sched.h>
#include <minos/kobject.h>

#include <libminos/blkdev.h>
#include <libminos/barrier.h>

#include "virtio.h"

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
	struct list_head list;
	struct blkdev blkdev;
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

static int virtio_blk_poll(struct blkdev *blkdev, struct blkreq *req)
{
	struct virtio_blk *blk = get_vblkdev(blkdev);
	int ret;

	ret = kobject_read(blk->intid, NULL, 0, NULL, NULL, 0, NULL, -1);
	if (ret != 0)
		return ret;

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

static int virtio_blk_status(struct blkdev *dev)
{
	struct virtio_blk *blkdev = get_vblkdev(dev);
	// printf("virtio_blk_dev at 0x%x\n",
	//       kmem_lookup_phys((void *)blkdev->regs));
	printf("    Status=0x%x\n", READ32(blkdev->regs->Status));
	printf("    DeviceID=0x%x\n", READ32(blkdev->regs->DeviceID));
	printf("    VendorID=0x%x\n", READ32(blkdev->regs->VendorID));
	printf("    InterruptStatus=0x%x\n",
	       READ32(blkdev->regs->InterruptStatus));
	printf("    MagicValue=0x%x\n", READ32(blkdev->regs->MagicValue));
	printf("  Queue 0:\n");
	printf("    avail.idx = %u\n", blkdev->virtq->avail->idx);
	printf("    used.idx = %u\n", blkdev->virtq->used->idx);
	WRITE32(blkdev->regs->QueueSel, 0);
	mb();
	printf("    ready = 0x%x\n", READ32(blkdev->regs->QueueReady));
	virtq_show(blkdev->virtq);
	return 0;
}

static struct blkreq *virtio_blk_alloc(struct blkdev *dev)
{
	struct virtio_blk_req *vblkreq;
	
	vblkreq = kzalloc(sizeof(struct virtio_blk_req));
	if (!vblkreq)
		return NULL;

	return &vblkreq->blkreq;
}

static void virtio_blk_free(struct blkdev *dev, struct blkreq *req)
{
	struct virtio_blk_req *vblkreq = get_vblkreq(req);
	kfree(vblkreq);
}

static int virtio_blk_submit(struct blkdev *dev, struct blkreq *req)
{
	struct virtio_blk *blk = get_vblkdev(dev);
	struct virtio_blk_req *hdr = get_vblkreq(req);
	uint32_t d1, d2, d3, datamode = 0;

	if (req->type == BLKREQ_READ) {
		hdr->type = VIRTIO_BLK_T_IN;
		datamode = VIRTQ_DESC_F_WRITE; /* mark page writeable */
		/*
		 * touch the req memory buf, to ensure it has been mapped
		 * by the kernel, so we can get the right physical memory
		 * address later. this buffer may in different page, so need
		 * twice. TBD
		 */
		memset(req->buf, 0, 4);
		memset(req->buf + VIRTIO_BLK_SECTOR_SIZE - 4, 0, 4);
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

struct blkdev_ops virtio_blk_ops = {
	.alloc = virtio_blk_alloc,
	.free = virtio_blk_free,
	.submit = virtio_blk_submit,
	.status = virtio_blk_status,
	.poll = virtio_blk_poll,
};

#define __raw_read8(a)	(*(volatile uint8_t *)(a))

static void get_config(void *base, unsigned offset, void *buf, unsigned len)
{
	uint8_t *ptr = buf;
	int i;

	for (i = 0; i < len; i++)
		ptr[i] = __raw_read8(base + offset + i);
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
	vdev->blkdev.ops = &virtio_blk_ops;
	vdev->blkdev.sector_size = VIRTIO_BLK_SECTOR_SIZE;
	vdev->blkdev.pages_per_sector = 1;

	/* capacity is 64 bit, configuration reg read is not atomic */
	do {
		genbefore = READ32(vdev->regs->ConfigGeneration);
		get_config((void *)regs, 0x100, &vdev->config,
				sizeof(struct virtio_blk_config));
		genafter = READ32(vdev->regs->ConfigGeneration);
	} while (genbefore != genafter);

	vdev->blkdev.sector_cnt = vdev->config.capacity;
	printf("vd0 capacity : %ldMB\n", vdev->config.capacity * VIRTIO_BLK_SECTOR_SIZE / 1024 / 1024);

	WRITE32(regs->Status, READ32(regs->Status) | VIRTIO_STATUS_DRIVER_OK);
	mb();

	register_blkdev(&vdev->blkdev, 0, 0);

	return 0;
}
