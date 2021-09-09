#ifndef __LIBMINOS_BLK_DEV_H__
#define __LIBMINOS_BLK_DEV_H__

#include <inttypes.h>
#include <minos/list.h>
#include <minos/types.h>
#include <minos/spinlock.h>

#define BLKREQ_READ	0x0
#define BLKREQ_WRITE	0x1

#define BLKREQ_INIT 0x0
#define BLKREQ_OK 0x1
#define BLKREQ_ERR 0x2

#define BLKDEV_NAME_SIZE 16
#define BLKDEV_MAX_PARTITIONS 8

#define BLKDEV_STACK_SIZE	(32 * 1024)

struct partition;
struct blkdev;
struct super_block;

struct blkreq {
	int type;
	uint64_t blkidx;		// which block need to read. default block size 4096
	uint64_t size;			// blkreq buf size
	uint8_t *buf;			// blkreq buf address.
	int status;			// blkreq status.
	void *pdata;			// the private data for the realy device req if has.
	struct list_head list;
};

struct blkdev_ops {
	struct blkreq *(*alloc)(struct blkdev *dev);
	void (*free)(struct blkdev *dev, struct blkreq *req);
	int (*submit)(struct blkdev *dev, struct blkreq *req);
	int (*poll)(struct blkdev *dev, struct blkreq *req);
	int (*status)(struct blkdev *dev);
};

#define PARTITION_STAT_OK		0x0
#define PARTITION_STAT_SB_FAIL		0x1
#define PARTITION_STAT_FS_UNSUPPORT	0x2

#define BLKDEV_NAME_SIZE 16

struct partition {
	int type;
	int partid;
	int stat;
	uint64_t sector_cnt;
	uint64_t lba;
	struct blkdev *blkdev;
	struct super_block *sb;
};

struct vfs_server;
struct vfs_server_ops;

struct blkdev {
	int id;
	int nrpart;
	int dma_handle;
	uint32_t sector_size;
	uint64_t sector_cnt;
	uint64_t data_sector_start; 
	int pages_per_sector;
	struct blkdev_ops *ops;
	spinlock_t lock;
	struct partition *partitions[BLKDEV_MAX_PARTITIONS];
	struct vfs_server *vfs_servers[BLKDEV_MAX_PARTITIONS];

	char name[BLKDEV_NAME_SIZE];
};

#define bdev_sector_pages(bdev, nr)	\
	PAGE_NR(((nr) * bdev->sector_size))

int read_blkdev_sectors(struct blkdev *bdev,
		void *buf, off_t start, size_t cnt);

int write_blkdev_sectors(struct blkdev *bdev,
		void *buf, off_t start, size_t cnt);

int submit_blkreq_many(struct blkdev *bdev,
		struct list_head *breq_list);

int submit_blkreq_one(struct blkdev *bdev, struct blkreq *breq);

int register_blkdev(struct blkdev *bdev,
		struct vfs_server_ops *vops, int flags, int gpt);

#endif
