/*
 * Copyright (c) 2021 - 2021 Min Le (lemin9538@163.com)
 */

#include <errno.h>
#include <minos/debug.h>
#include <minos/sched.h>
#include <minos/kmalloc.h>
#include <minos/compiler.h>
#include <minos/thread.h>
#include <sys/epoll.h>
#include <minos/kobject.h>
#include <minos/proto.h>
#include <minos/service.h>

#include <libminos/blkdev.h>
#include <libminos/vfs.h>

#define MAX_EPFD 10

hidden extern int parse_mbr(struct blkdev *blkdev);
hidden extern struct filesystem *lookup_filesystem(unsigned char type);

static int start_blkdev_server(struct blkdev *blkdev, struct vfs_server_ops *vops)
{
	char name[BLKDEV_NAME_SIZE * 2];
	struct partition *part;
	struct vfs_server *vs;
	int i;

	for (i = 0; i < blkdev->nrpart; i++) {
		part = blkdev->partitions[i];
		if (!part || part->stat != PARTITION_STAT_OK)
			continue;

		sprintf(name, "%sp%d", blkdev->name, i);
		vs = create_vfs_server(name, vops, part);
		if (!vs)
			pr_err("create vfs fail for %s\n", name);
		else
			blkdev->vfs_servers[i] = vs;
	}

	if (blkdev->nrpart == 1) {
		if (blkdev->vfs_servers[0])
			run_vfs_server(blkdev->vfs_servers[0], 0);
		return -EIO;
	} else {
		for (i = 0; i < blkdev->nrpart; i++) {
			if (blkdev->vfs_servers[i])
				run_vfs_server(blkdev->vfs_servers[i], 1);
		}
	}

	return 0;
}

int register_blkdev(struct blkdev *blkdev, struct vfs_server_ops *vops,  int flags, int gpt)
{
	struct partition *part;
	struct filesystem *fs;
	int i, ret;

	if (!vops)
		return -EINVAL;

	/*
	 * read the first block 
	 */
	if (gpt) {
		pr_warn("GPT partions is not supported\n");
		return -EPROTONOSUPPORT;
	} else {
		parse_mbr(blkdev);
	}

	if (blkdev->nrpart == 0) {
		pr_warn("NO partitions found on this blkdev\n");
		return -ENODEV;
	}

	for (i = 0; i < blkdev->nrpart; i++) {
		part = blkdev->partitions[i];
		fs = lookup_filesystem(part->type);
		if (!fs) {
			part->stat = PARTITION_STAT_FS_UNSUPPORT;
			pr_err("Filesystem %d not support\n", part->type);
			continue;
		}

		ret = fs->read_super(part, fs);
		if (ret) {
			part->stat = PARTITION_STAT_SB_FAIL;
			pr_err("Create super block failed\n");
			continue;
		}
	}

	return start_blkdev_server(blkdev, vops);
}

static int blkreq_wait_all(struct blkdev *bdev, struct list_head *breq_list)
{
	struct blkreq *breq;

	list_for_each_entry(breq, breq_list, list) {
		if (breq->status != 0)
			continue;

		while (breq->status == 0) {
			if (bdev->ops->poll)
				bdev->ops->poll(bdev, breq);
			else
				yield();
		}
	}

	list_for_each_entry(breq, breq_list, list) {
		if (breq->status == BLKREQ_ERR)
			return BLKREQ_ERR;
	}

	return BLKREQ_OK;
}

int submit_blkreq_one(struct blkdev *bdev, struct blkreq *breq)
{
	int ret;

	ret = bdev->ops->submit(bdev, breq);
	if (ret)
		return ret;

	while (breq->status == 0)
		yield();

	return (breq->status == BLKREQ_ERR);
}

int submit_blkreq_many(struct blkdev *bdev, struct list_head *breq_list)
{
	struct blkreq *breq;
	int ret, status;

	if (is_list_empty(breq_list)) {
		pr_err("block request list is empty\n");
		return -EINVAL;
	}

	list_for_each_entry(breq, breq_list, list) {
		ret = bdev->ops->submit(bdev, breq);
		if (ret) {
			ret = -EIO;
			break;
		}
	}

	status = blkreq_wait_all(bdev, breq_list);
	if (status != BLKREQ_OK)
		ret = -EIO;

	return ret;
}

static int __request_blkdev_sectors(struct blkdev *bdev, void *buf,
		off_t start, size_t cnt, int op)
{
	LIST_HEAD(blkreq_list);
	struct blkreq *breq, *next;
	int i, ret = 0, status;

	for (i = 0; i < cnt; i++) {
		breq = bdev->ops->alloc(bdev);
		if (!breq) {
			ret = -ENOMEM;
			goto out;
		}

		breq->blkidx = start + i;
		breq->type = op;
		breq->buf = buf + i * bdev->sector_size;
		breq->size = bdev->sector_size;
		ret = bdev->ops->submit(bdev, breq);
		if (ret) {
			bdev->ops->free(bdev, breq);
			ret = -EIO;
			break;
		}
		list_add_tail(&blkreq_list, &breq->list);
	}

	status = blkreq_wait_all(bdev, &blkreq_list);
	if (status != BLKREQ_OK)
		ret = -EIO;

out:
	list_for_each_entry_safe(breq, next, &blkreq_list, list) {
		list_del(&breq->list);
		bdev->ops->free(bdev, breq);
	}

	return ret;
}

int read_blkdev_sectors(struct blkdev *bdev,
		void *buf, off_t start, size_t cnt)
{
	return __request_blkdev_sectors(bdev, buf, start, cnt, BLKREQ_READ);
}

int write_blkdev_sectors(struct blkdev *bdev,
		void *buf, off_t start, size_t cnt)
{
	return __request_blkdev_sectors(bdev, buf, start, cnt, BLKREQ_WRITE);
}
