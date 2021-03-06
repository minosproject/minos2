/**
 * virtio declarations (mmio, queue)
 */

#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <minos/list.h>
#include <minos/device.h>

#define VIRTIO_MAGIC   0x74726976
#define VIRTIO_VERSION 0x2
#define VIRTIO_DEV_NET 0x1
#define VIRTIO_DEV_BLK 0x2
#define wrap(x, len)   ((x) & ~(len))

/*
 * See Section 4.2.2 of VIRTIO 1.0 Spec:
 * http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html
 */
typedef volatile struct __attribute__((packed)) {
	uint32_t MagicValue;		// 00
	uint32_t Version;		// 04
	uint32_t DeviceID;		// 08
	uint32_t VendorID;		// 0c
	uint32_t DeviceFeatures;	// 10
	uint32_t DeviceFeaturesSel;	// 14
	uint32_t _reserved0[2];		// 18 1c
	uint32_t DriverFeatures;	// 20
	uint32_t DriverFeaturesSel;	// 24
	uint32_t GuestPageSize;		// 28
	uint32_t _reserved1[1];		// 2c
	uint32_t QueueSel;		// 30
	uint32_t QueueNumMax;		// 34
	uint32_t QueueNum;		// 38
	uint32_t QueueAlign;		// 3c
	uint32_t QueuePfn;		// 40
	uint32_t QueueReady;		// 44
	uint32_t _reserved3[2];		// 48 4c
	uint32_t QueueNotify;		// 50
	uint32_t _reserved4[3];		// 54 58 5c
	uint32_t InterruptStatus;	// 60
	uint32_t InterruptACK;		// 64
	uint32_t _reserved5[2];		// 68 6c
	uint32_t Status;		// 70
	uint32_t _reserved6[3];
	uint32_t QueueDescLow;
	uint32_t QueueDescHigh;
	uint32_t _reserved7[2];
	uint32_t QueueAvailLow;
	uint32_t QueueAvailHigh;
	uint32_t _reserved8[2];
	uint32_t QueueUsedLow;
	uint32_t QueueUsedHigh;
	uint32_t _reserved9[21];
	uint32_t ConfigGeneration;
	uint32_t Config[0];
} virtio_regs;

#define VIRTIO_STATUS_ACKNOWLEDGE        (1)
#define VIRTIO_STATUS_DRIVER             (2)
#define VIRTIO_STATUS_FAILED             (128)
#define VIRTIO_STATUS_FEATURES_OK        (8)
#define VIRTIO_STATUS_DRIVER_OK          (4)
#define VIRTIO_STATUS_DEVICE_NEEDS_RESET (64)

struct virtio_cap {
	char *name;
	uint32_t bit;
	bool support;
	char *help;
};

struct virtqueue_desc {
	uint64_t addr;
	uint32_t len;
/* This marks a buffer as continuing via the next field. */
#define VIRTQ_DESC_F_NEXT 1
/* This marks a buffer as device write-only (otherwise device read-only). */
#define VIRTQ_DESC_F_WRITE 2
/* This means the buffer contains a list of buffer descriptors. */
#define VIRTQ_DESC_F_INDIRECT 4
	/* The flags as indicated above. */
	uint16_t flags;
	/* Next field if flags & NEXT */
	uint16_t next;
} __attribute__((packed));

struct virtqueue_avail {
#define VIRTQ_AVAIL_F_NO_INTERRUPT 1
	uint16_t flags;
	uint16_t idx;
	uint16_t ring[0];
} __attribute__((packed));

struct virtqueue_used_elem {
	uint32_t id;
	uint32_t len;
} __attribute__((packed));

struct virtqueue_used {
#define VIRTQ_USED_F_NO_NOTIFY 1
	uint16_t flags;
	uint16_t idx;
	struct virtqueue_used_elem ring[0];
} __attribute__((packed));

/*
 * For simplicity, we lay out the virtqueue in contiguous memory on a single
 * page. See virtq_create for the layout and alignment requirements.
 */
struct virtqueue {
	/* Physical base address of the full data structure. */
	unsigned long vq_phys;
	unsigned long vq_virt;
	size_t len;
	size_t seen_used;
	size_t free_desc;

	volatile struct virtqueue_desc *desc;
	volatile struct virtqueue_avail *avail;
	volatile struct virtqueue_used *used;

	volatile uint16_t *used_event;
	volatile uint16_t *avail_event;
	void *desc_virt[0];
} __attribute__((packed));

struct virtio_blk_config {
	uint64_t capacity;
	uint32_t size_max;
	uint32_t seg_max;
	struct {
		uint16_t cylinders;
		uint8_t heads;
		uint8_t sectors;
	} geometry;
	uint32_t blk_size;
	struct {
		uint8_t physical_block_exp;
		uint8_t alignment_offset;
		uint16_t min_io_size;
		uint32_t opt_io_size;
	} topology;
	uint8_t writeback;
} __attribute__((packed));

struct virtio_net_config {
	uint8_t mac[6];
#define VIRTIO_NET_S_LINK_UP  1
#define VIRTIO_NET_S_ANNOUNCE 2
	uint16_t status;
	uint16_t max_virtqueue_pairs;
} __attribute__((packed));

#define BLKREQ_READ	0x0
#define BLKREQ_WRITE	0x1

#define BLKREQ_INIT 0x0
#define BLKREQ_OK 0x1
#define BLKREQ_ERR 0x2

struct blkreq {
	int type;
	uint64_t blkidx;		// which block need to read. default block size 4096
	uint64_t size;			// blkreq buf size
	uint8_t *buf;			// blkreq buf address.
	int status;			// blkreq status.
	void *pdata;			// the private data for the realy device req if has.
	struct list_head list;
};

#define VIRTIO_BLK_REQ_HEADER_SIZE 16
#define VIRTIO_BLK_REQ_FOOTER_SIZE 1
struct virtio_blk_req {
#define VIRTIO_BLK_T_IN    0
#define VIRTIO_BLK_T_OUT   1
#define VIRTIO_BLK_T_SCSI  2
#define VIRTIO_BLK_T_FLUSH 4
	uint32_t type;
	uint32_t reserved;
	uint64_t sector;
	uint8_t status;
	/* end standard fields, begin helpers */
	uint8_t _pad[3];
	uint32_t descriptor;
	struct blkreq blkreq;
} __attribute__((packed));

#define VIRTIO_BLK_SECTOR_SIZE 512

#define VIRTIO_BLK_S_OK     0
#define VIRTIO_BLK_S_IOERR  1
#define VIRTIO_BLK_S_UNSUPP 2

/*
 * virtqueue routines
 */
struct virtqueue *virtq_create(virtio_regs *regs, uint32_t len);
uint32_t virtq_alloc_desc(struct virtqueue *virtq, void *addr);
void virtq_free_desc(struct virtqueue *virtq, uint32_t desc);
void virtq_add_to_device(volatile virtio_regs *regs, struct virtqueue *virtq,
                         uint32_t queue_sel);
void virtq_show(struct virtqueue *virtq);

/*
 * General purpose routines for virtio drivers
 */
void virtio_check_capabilities(virtio_regs *device, struct virtio_cap *caps,
                               uint32_t n, char *whom);

#define VIRTIO_INDP_CAPS                                                       \
	{ "VIRTIO_F_RING_INDIRECT_DESC", 28, false,                            \
	  "Negotiating this feature indicates that the driver can use"         \
	  " descriptors with the VIRTQ_DESC_F_INDIRECT flag set, as"           \
	  " described in 2.4.5.3 Indirect Descriptors." },                     \
	{ "VIRTIO_F_RING_EVENT_IDX", 29, false,                        	       \
	  "This feature enables the used_event and the avail_event "           \
	  "fields as described in 2.4.7 and 2.4.8." },                         \
	{ "VIRTIO_F_VERSION_1", 32, false,                                     \
	  "This indicates compliance with this specification, giving "         \
	  "a simple way to detect legacy devices or drivers." },

int virtio_dev_init(unsigned long virt, uint32_t intid);

int virtio_blk_init(virtio_regs *regs, uint32_t intid);
