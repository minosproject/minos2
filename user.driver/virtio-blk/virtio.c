/**
 * Implements virtio device drivers, particularly mmio ones.
 *
 * Reference:
 *
 * http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <minos/debug.h>
#include <minos/kobject.h>
#include <minos/types.h>

#include "virtio.h"

#define VIRTQ_ALIGN(x)	(((x) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

static inline unsigned int virtq_size(unsigned int qsz)
{
	return VIRTQ_ALIGN(sizeof(struct virtqueue_desc) * qsz + sizeof(uint16_t) * (3 + qsz)) +
		VIRTQ_ALIGN(sizeof(uint16_t) * 3 + sizeof(struct virtqueue_used_elem) * qsz);
}

struct virtqueue *virtq_create(virtio_regs *regs, uint32_t len)
{
	int i, pma_handle;
	void *page_virt = 0;
	struct virtqueue *virtq;
	uint32_t max_queue_size;
	uint32_t memsize;

	max_queue_size = READ32(regs->QueueNumMax);
	if (len > max_queue_size) {
		printf("virtio queue size not ready or too big %d %d\n",
				len, max_queue_size);
		len = max_queue_size;
	}

	virtq = zalloc(sizeof(struct virtqueue) + sizeof(void *) * len);
	if (!virtq)
		return NULL;

	/*
	 * allocate the total virtq ring size, must PAGE_SIZE alignment.
	 */
	memsize = virtq_size(len);
	pr_info("virtio-blk virtq size %d\n", memsize);

	pma_handle = request_consequent_pma(memsize);
	if (pma_handle <= 0)
		return NULL;

	page_virt = kobject_mmap(pma_handle);
	if (page_virt == (void *)-1) {
		free(virtq);
		kobject_close(pma_handle);
		return NULL;
	}

	/*
	 * clear it, than kernel will handle page fault for
	 * this page.
	 */
	memset(page_virt, 0, memsize);
	virtq->len = len;
	virtq->vq_virt = (unsigned long)page_virt;
	virtq->vq_phys = kobject_ctl(0, KOBJ_PROCESS_VA2PA, (unsigned long)page_virt);
	if (virtq->vq_phys == -1) {
		free(virtq);
		kobject_close(pma_handle);
		return NULL;
	}

	virtq->desc = (struct virtqueue_desc *)page_virt;
	virtq->avail = page_virt + len * sizeof(struct virtqueue_desc);
	virtq->used = (void *)&virtq->avail->ring[len];
	virtq->used = (void *)VIRTQ_ALIGN((unsigned long)virtq->used);

	virtq->avail->idx = 0;
	virtq->used->idx = 0;
	virtq->seen_used = virtq->used->idx;
	virtq->free_desc = 0;

	for (i = 0; i < len; i++) {
		virtq->desc[i].next = i + 1;
	}

	return virtq;
}

uint32_t virtq_alloc_desc(struct virtqueue *virtq, void *addr)
{
	uint32_t desc = virtq->free_desc;
	uint32_t next = virtq->desc[desc].next;
	if (desc == virtq->len)
		printf("ran out of virtqueue descriptors\n");
	virtq->free_desc = next;

	virtq->desc[desc].addr = kobject_ctl(0, KOBJ_PROCESS_VA2PA,
			(unsigned long)addr);
	if (virtq->desc[desc].addr == -1) {
		pr_err("translate VA to PA failed\n");
		exit(-EFAULT);
	}

	virtq->desc_virt[desc] = addr;
	return desc;
}

void virtq_free_desc(struct virtqueue *virtq, uint32_t desc)
{
	virtq->desc[desc].next = virtq->free_desc;
	virtq->free_desc = desc;
	virtq->desc_virt[desc] = NULL;
}

#define U64_HIGH(addr)	(uint32_t)((uint64_t)(addr) >> 32)
#define U64_LOW(addr)	(uint32_t)((uint64_t)(addr) & 0xffffffff)
#define nop()		asm volatile ("nop\n");

static void virtq_add_to_device_legacy(volatile virtio_regs *regs,
			struct virtqueue *virtq, uint32_t queue_sel)
{
	WRITE32(regs->QueueSel, queue_sel);
	while (READ32(regs->QueuePfn) != 0)
		nop();

	WRITE32(regs->QueueNum, virtq->len);
	WRITE32(regs->QueueAlign, PAGE_SIZE);
	WRITE32(regs->QueuePfn, virtq->vq_phys >> PAGE_SHIFT);
}

static void virtq_add_to_device_common(volatile virtio_regs *regs,
		struct virtqueue *virtq, uint32_t queue_sel)
{
	uint64_t address;

	WRITE32(regs->QueueSel, queue_sel);
	while (READ32(regs->QueueReady) != 0)
		nop();

	WRITE32(regs->QueueNum, virtq->len);
	mb();

	address = virtq->vq_phys + (unsigned long)virtq->desc - virtq->vq_virt;
	WRITE32(regs->QueueDescLow, U64_LOW(address));
	WRITE32(regs->QueueDescHigh, U64_HIGH(address));

	address = virtq->vq_phys + (unsigned long)virtq->avail - virtq->vq_virt;
	WRITE32(regs->QueueAvailLow, U64_LOW(address));
	WRITE32(regs->QueueAvailHigh, U64_HIGH(address));

	address = virtq->vq_phys + (unsigned long)virtq->used - virtq->vq_virt;
	WRITE32(regs->QueueUsedLow, U64_LOW(address));
	WRITE32(regs->QueueUsedHigh, U64_HIGH(address));

	mb();
	WRITE32(regs->QueueReady, 1);
}

void virtq_add_to_device(volatile virtio_regs *regs,
		struct virtqueue *virtq, uint32_t queue_sel)
{
	if (READ32(regs->Version) == 1)
		virtq_add_to_device_legacy(regs, virtq, queue_sel);
	else
		virtq_add_to_device_common(regs, virtq, queue_sel);
}

void virtq_show(struct virtqueue *virtq)
{
	int count = 0;
	uint32_t i = virtq->free_desc;
	printf("Current free_desc: %lu, len=%lu\n", virtq->free_desc, virtq->len);
	while (i != virtq->len && count++ <= virtq->len) {
		printf("  next: %u -> %u\n", i, virtq->desc[i].next);
		i = virtq->desc[i].next;
	}
	if (count > virtq->len) {
		puts("Overflowed descriptors?\n");
	}
}

void virtio_check_capabilities(virtio_regs *regs, struct virtio_cap *caps,
                               uint32_t n, char *whom)
{
	uint32_t i;
	uint32_t bank = 0;
	uint32_t driver = 0;
	uint32_t device;

	WRITE32(regs->DeviceFeaturesSel, bank);
	mb();
	device = READ32(regs->DeviceFeatures);

	for (i = 0; i < n; i++) {
		if (caps[i].bit / 32 != bank) {
			/* Time to write our selected bits for this bank */
			WRITE32(regs->DriverFeaturesSel, bank);
			mb();
			WRITE32(regs->DriverFeatures, driver);
			if (device) {
				printf("%s: device supports unknown bits"
				       " 0x%x in bank %u\n", whom, device,bank);
			}
			/* Now we set these variables for next time. */
			bank = caps[i].bit / 32;
			WRITE32(regs->DeviceFeaturesSel, bank);
			mb();
			device = READ32(regs->DeviceFeatures);
		}
		if (device & (1 << caps[i].bit)) {
			if (caps[i].support) {
				driver |= (1 << caps[i].bit);
			} else {
				printf("virtio supports unsupported option %s (%s)\n",
				       caps[i].name, caps[i].help);
			}
			/* clear this from device now */
			device &= ~(1 << caps[i].bit);
		}
	}

	/* Time to write our selected bits for this bank */
	WRITE32(regs->DriverFeaturesSel, bank);
	mb();
	WRITE32(regs->DriverFeatures, driver);
	if (device) {
		printf("%s: device supports unknown bits"
		       " 0x%x in bank %u\n", whom, device, bank);
	}
}

int virtio_dev_init(unsigned long virt, uint32_t intid)
{
	virtio_regs *regs = (virtio_regs *)virt;

	if (READ32(regs->MagicValue) != VIRTIO_MAGIC) {
		printf("error: virtio at 0x%lx had wrong magic value 0x%x, "
		       "expected 0x%x\n",
		       virt, regs->MagicValue, VIRTIO_MAGIC);
		return -1;
	}

	if (READ32(regs->Version) == 1) {
		printf("virtio-dev: legacy mode\n");
		WRITE32(regs->GuestPageSize, PAGE_SIZE);
	}

	if (READ32(regs->DeviceID) == 0) {
		/*On QEMU, this is pretty common, don't print a message */
		/*printf("warn: virtio at 0x%x has DeviceID=0, skipping\n",
		 * virt);*/
		return -1;
	}

	/* First step of initialization: reset */
	WRITE32(regs->Status, 0);
	mb();
	/* Hello there, I see you */
	WRITE32(regs->Status, READ32(regs->Status) | VIRTIO_STATUS_ACKNOWLEDGE);
	mb();

	/* Hello, I am a driver for you */
	WRITE32(regs->Status, READ32(regs->Status) | VIRTIO_STATUS_DRIVER);
	mb();

	switch (READ32(regs->DeviceID)) {
	case VIRTIO_DEV_BLK:
		return virtio_blk_init(regs, intid);
	default:
		printf("unsupported virtio device ID 0x%x\n",
		       READ32(regs->DeviceID));
	}
	return 0;
}
