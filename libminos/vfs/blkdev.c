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

#include <libminos/blkdev.h>
#include <libminos/vfs.h>
#include "fs.h"

hidden extern int parse_mbr(struct blkdev *blkdev);
hidden extern struct filesystem *lookup_filesystem(unsigned char type);

static int handle_vfs_open(struct partition *part,
		struct proto *proto, char *path, size_t size)
{
	struct file *file;
	struct epoll_event event;

	if (size >= FILENAME_MAX) {
		kobject_reply(part->epfd, 0, -EINVAL, 0, 0);
		return -EINVAL;
	}

	path[size] = 0;
	file = vfs_open(part, path, proto->open.flags, proto->open.mode);
	if (!file) {
		kobject_reply(part->epfd, 0, -ENOMEM, 0, 0);
		return -ENOMEM;
	}

	event.events = EPOLLIN;
	event.data.ptr = file;

	epoll_ctl(part->epfd, EPOLL_CTL_ADD, file->handle, &event);
	kobject_reply(part->ctl_fd, 0, 0, file->handle,
			KOBJ_RIGHT_WRITE | KOBJ_RIGHT_MMAP);

	return 0;
}

static int handle_vfs_read(struct partition *part,
		struct proto *proto)
{
	return 0;
}

static int handle_vfs_request(struct partition *part, struct epoll_event *event)
{
	struct proto proto;
	char path[FILENAME_MAX];
	long ret;
	size_t ad, ae;

	ret = kobject_read(event->data.fd, &proto, sizeof(struct proto),
			&ad, path, FILENAME_MAX, &ae, 0);
	if (ret < 0)
		return ret;

	switch (proto.proto_id) {
	case PROTO_OPEN:
		handle_vfs_open(part, &proto, path, ae);
		break;
	case PROTO_READ:
		handle_vfs_read(part, &proto);
		break;
	case PROTO_WRITE:
		break;
	default:
		break;
	}

	return 0;
}

static int partition_thread(void *data)
{
#define MAX_EPFD 10
	struct endpoint_create_arg args = {
		.mode = EP_MODE_MUTIL_WRITER,
		.shmem_size = 0,
	};
	struct epoll_event events[MAX_EPFD];
	struct epoll_event *event = &events[0];
	int epfd, cfd, cnt, i;
	struct partition *part = data;

	cfd = kobject_create("disk0", KOBJ_TYPE_ENDPOINT,
			KOBJ_RIGHT_RW | KOBJ_RIGHT_POLL,
			KOBJ_RIGHT_READ, (unsigned long)&args);
	if (cfd < 0)
		return cfd;

	epfd = epoll_create(1);
	if (epfd < 0)
		return epfd;

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, event))
		return -1;

	part->epfd = epfd;
	part->ctl_fd = cfd;

	for (;;) {
		cnt = epoll_wait(epfd, events, MAX_EPFD, -1);
		if (cnt <= 0)
			continue;

		for (i = 0; i < cnt; i++)
			handle_vfs_request(part, &events[i]);
	}

	return -1;
}

static int register_partition(struct partition *part)
{
	void *stack;
	int ret;

	if (part == NULL)
		return -EINVAL;

	/*
	 * one more pages for tls memory, 1 page is enough ? TBD
	 */
	stack = get_pages((BLKDEV_STACK_SIZE >> PAGE_SHIFT) + 1);
	if (!stack)
		return -ENOMEM;

	stack += BLKDEV_STACK_SIZE;
	ret = create_thread(partition_thread, stack, -1, -1, 0, stack, part);
	if (ret) {
		free_pages(stack);
		pr_err("create partition failed\n");
		return ret;
	}

	return 0;
}

int register_blkdev(struct blkdev *blkdev, unsigned long flags, int gpt)
{
	struct partition *part;
	LIST_HEAD(blkreq_list);
	struct filesystem *fs;
	int i, ret;

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
		part = &blkdev->partitions[i];
		fs = lookup_filesystem(part->type);
		if (!fs) {
			part->stat = BLKDEV_STAT_FS_UNSUPPORT;
			pr_err("Filesystem %d not support\n", part->type);
			continue;
		}

		ret = fs->create_super_block(part, fs);
		if (ret) {
			part->stat = BLKDEV_STAT_SB_FAIL;
			pr_err("Create super block failed\n");
			continue;
		}

		part->fs = fs;
	}

	if (blkdev->nrpart > 1) {
		for (i = 0; i < blkdev->nrpart; i++) {
			part = &blkdev->partitions[i];
			if (part->stat != 0)
				continue;

			ret = register_partition(part);
			pr_notice("Register partition %s\n",
					ret ? "fail" : "success");
		}
	} else {
		partition_thread(&blkdev->partitions[0]);
	}

	return 0;
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
