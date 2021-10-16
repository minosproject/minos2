/*
 * Copyright (c) 2021 Min Le (lemin9538@163.com)
 */

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/epoll.h>

#include <minos/kobject.h>
#include <minos/map.h>
#include <minos/debug.h>
#include <minos/proto.h>
#include <minos/service.h>
#include <minos/types.h>

#include <ext4.h>
#include <ext4_mbr.h>

#define EXT4_MAX_PARTITION 4
#define VFS_MAX_EVENTS 16

struct lwext4_file {
	int handle;
	uint8_t root;
	uint8_t dir;
	char *sbuf;
	size_t sbuf_size;
	char *buf[0];
};

/*
 * only support one partition now.
 */
struct ext4_server {
	int epfd;
	struct lwext4_file root_file;
	char buf[PAGE_SIZE];
	struct ext4_blockdev bdev;
};

#define LWEXT4_FILE(lwf) (struct ext4_file *)((lwf)->buf)
#define LWEXT4_DIR(lwf) (struct ext4_dir *)((lwf)->buf)

static int ext4_server_listen(struct ext4_server *vs, struct lwext4_file *file)
{
	struct epoll_event event;
	int ret;

	event.events = EPOLLIN | EPOLLWCLOSE;
	event.data.ptr = file;
	ret = epoll_ctl(vs->epfd, EPOLL_CTL_ADD, file->handle, &event);
	if (ret)
		pr_err("add file to vfs server failed\n");

	return 0;
}

static int ext4_server_unlisten(struct ext4_server *vs, struct lwext4_file *file)
{
	struct epoll_event event;
	int ret;

	event.events = EPOLLIN | EPOLLWCLOSE;
	ret = epoll_ctl(vs->epfd, EPOLL_CTL_ADD, file->handle, &event);
	if (ret)
		pr_err("unlisten ext4 file failed\n");

	return ret;
}

static struct lwext4_file *create_new_lwext4_file(int dir)
{
	struct lwext4_file *file;
	int handle;
	void *addr;
	int size;

	handle = kobject_create_endpoint(PAGE_SIZE);
	if (handle <= 0)
		return NULL;

	addr = kobject_mmap(handle);
	if (addr == (void *)-1) {
		kobject_close(handle);
		return NULL;
	}

	size = sizeof(struct lwext4_file);
	if (dir)
		size += sizeof(struct ext4_dir);
	else
		size += sizeof(struct ext4_file);

	file = zalloc(size);
	if (!file)
		return NULL;

	file->handle = handle;
	file->sbuf = addr;
	file->sbuf_size = PAGE_SIZE;

	return file;
}

static void release_file(struct lwext4_file *file)
{
	if (!file)
		return;

	kobject_munmap(file->handle);
	kobject_close(file->handle);
	free(file);
}

static int __handle_vfs_open_request(struct ext4_server *vs, struct lwext4_file *file,
		struct proto *proto, struct lwext4_file **new)
{
	int dir = !!(proto->open.flags & O_DIRECTORY);
	struct lwext4_file *new_file;
	int ret;

	if (!file->dir)
		return -ENOTDIR;

	new_file = create_new_lwext4_file(dir);
	if (!new_file)
		return -ENOMEM;

	if (dir)
		ret = ext4_dir_open(LWEXT4_DIR(new_file), vs->buf);
	else
		ret = ext4_fopen(LWEXT4_FILE(new_file), vs->buf, "r");
	if (ret) {
		pr_err("open %s failed\n", vs->buf);
		release_file(new_file);
		return -ENOENT;
	}

	ret = ext4_server_listen(vs, new_file);
	if (ret) {
		pr_err("add new file failed %s\n", __func__);
		release_file(new_file);
		return ret;
	}

	*new = new_file;

	return 0;
}

static int handle_vfs_open_request(struct ext4_server *vs,
			struct lwext4_file *parent, struct proto *proto)
{
	struct lwext4_file *file;
	int ret;

	ret = __handle_vfs_open_request(vs, parent, proto, &file);
	if (ret) {
		kobject_reply_errcode(parent->handle, proto->token, ret);
		return ret;
	}

	kobject_reply_handle(parent->handle, proto->token,
			file->handle, KR_WM | KR_C);

	return 0;
}

static int handle_vfs_write_request(struct ext4_server *vs,
		struct lwext4_file *file, struct proto *proto)
{
	return 0;
}

static int handle_vfs_read_request(struct ext4_server *vs,
		struct lwext4_file *file, struct proto *proto)
{
	size_t ret_size;
	int ret;

	if (proto->read.len > PAGE_SIZE) {
		ret_size = -E2BIG;
		goto out;
	}

	ret = ext4_fread(LWEXT4_FILE(file), file->sbuf,
			proto->read.len, &ret_size);
	if (ret)
		pr_err("read file failed\n");
out:
	kobject_reply_errcode(file->handle, proto->token, ret_size);
	return 0;
}

static int handle_vfs_lseek_request(struct ext4_server *vs,
		struct lwext4_file *file, struct proto *proto)
{
	int ret;

	ret = ext4_fseek(LWEXT4_FILE(file), proto->lseek.off, proto->lseek.whence);
	kobject_reply_errcode(file->handle, proto->token, ret);

	return 0;
}

static int handle_vfs_getdent_request(struct ext4_server *vs,
		struct lwext4_file *file, struct proto *proto)
{
	const ext4_direntry *d;
	struct dirent *de;
	char *tmp = file->sbuf;
	int idx = 0, len;
	int size_left = PAGE_SIZE;

	if (!file->dir) {
		pr_err("file is not a directory\n");
		kobject_reply_errcode(file->handle, proto->token, -ENOTDIR);
	}

	while ((d = ext4_dir_entry_next(LWEXT4_DIR(file))) != NULL) {
		idx++;
		len = DIRENT_SIZE(d->name_length + 1);
		if (size_left < len)
			break;

		de = (struct dirent *)tmp;
		de->d_ino = d->inode;
		de->d_off = d->inode;
		de->d_reclen = len;
		de->d_type = d->inode_type;
		memcpy(de->d_name, d->name, d->name_length);
		de->d_name[d->name_length] = 0;

		tmp += len;
		size_left -= len;
	}

	kobject_reply_errcode(file->handle, proto->token, PAGE_SIZE - size_left);

	return 0;
}

static int handle_vfs_close_request(struct ext4_server *vs, struct lwext4_file *file)
{
	ext4_server_unlisten(vs, file);
	if (file->dir)
		ext4_dir_close(LWEXT4_DIR(file));
	else
		ext4_fclose(LWEXT4_FILE(file));

	release_file(file);

	return 0;
}

static int handle_vfs_in_request(struct ext4_server *vs, struct lwext4_file *file)
{
	struct proto proto;
	int ret;

	ret = kobject_read_proto_with_string(file->handle, &proto, vs->buf, PAGE_SIZE, 0);
	if (ret)
		return ret;

	switch (proto.proto_id) {
	case PROTO_OPEN:
		ret = handle_vfs_open_request(vs, file, &proto);
		break;
	case PROTO_READ:
		ret = handle_vfs_read_request(vs, file, &proto);
		break;
	case PROTO_WRITE:
		ret = handle_vfs_write_request(vs, file, &proto);
		break;
	case PROTO_GETDENT:
		ret = handle_vfs_getdent_request(vs, file, &proto);
		break;
	case PROTO_LSEEK:
		ret = handle_vfs_lseek_request(vs, file, &proto);
		break;
	default:
		ret = -ENOSYS;
		pr_err("unsupport vfs proto %d\n", proto.proto_id);
		kobject_reply_errcode(file->handle, proto.token, ret);
		break;
	}

#if 0
	if (ret)
		dump_proto(&proto);
#endif

	return ret;
}

static int handle_vfs_server_event(struct ext4_server *vs, struct epoll_event *event)
{
	struct lwext4_file *file = event->data.ptr;

	if (!file)
		return -ENOENT;

	if ((event->events != EPOLLIN) && (event->events != EPOLLWCLOSE))
		return -EPROTO;

	if (event->events == EPOLLWCLOSE)
		return handle_vfs_close_request(vs, file);
	else
		return handle_vfs_in_request(vs, file);
}

static int run_ext4_server(struct ext4_server *vs)
{
	struct epoll_event events[VFS_MAX_EVENTS];
	struct lwext4_file *efile = &vs->root_file;
	int epfd, rfd;
	int cnt, i;

	/*
	 * only support one partition now.
	 */
	rfd = register_service("/", "c", SRV_PORT, 0);
	if (rfd <= 0) {
		pr_err("create service for virtio-block ext4 server failed\n");
		return -ENOMEM;
	}

	epfd = epoll_create(0);
	if (epfd <= 0) {
		pr_err("create epoll handle for vfs server failed\n");
		unregister_service(rfd);
		return epfd;
	}

	vs->epfd = epfd;
	pr_info("ext4 server epfd:%d root_fd:%d\n", epfd, rfd);

	/*
	 * listen on the root file.
	 */
	memset(efile, 0, sizeof(struct lwext4_file));
	efile->handle = rfd;
	efile->root = 1;
	efile->dir = 1;
	ext4_server_listen(vs, efile);

	i_am_ok();
	pr_info("ext4 server start, waitting for request...\n");

	for (; ;) {
		cnt = epoll_wait(vs->epfd, events, VFS_MAX_EVENTS, -1);
		if (cnt <= 0)
			continue;

		for (i = 0; i < cnt; i++)
			handle_vfs_server_event(vs, &events[i]);
	}

	return -1;
}

int run_ext4_file_server(struct ext4_blockdev *bdev)
{
	struct ext4_mbr_bdevs bdevs;
	int r, i, cnt = 0;
	struct ext4_blockdev *ext4_blkdev = NULL;
	struct ext4_server *vs;

	vs = malloc(sizeof(struct ext4_server));
	if (!vs)
		return -ENOMEM;

	ext4_dmask_set(DEBUG_ALL);

	r = ext4_mbr_scan(bdev, &bdevs);
	if (r) {
		pr_err("ext4 mbr scan failed\n");
		return -ENODEV;
	}

	pr_info("ext4_mbr_scan:\n");

	for (i = 0; i < 4; i++) {
		pr_info("mbr_entry %d:\n", i);
		if (!bdevs.partitions[i].bdif) {
			pr_info("\tempty/unknown\n");
			continue;
		}
		
		pr_info("\toffeset: 0x%"PRIx64", %"PRIu64"MB\n",
				bdevs.partitions[i].part_offset,
				bdevs.partitions[i].part_offset / (1024 * 1024));
		pr_info("\tsize:    0x%"PRIx64", %"PRIu64"MB\n",
				bdevs.partitions[i].part_size,
				bdevs.partitions[i].part_size / (1024 * 1024));

		if (ext4_blkdev == NULL)
			ext4_blkdev = &bdevs.partitions[i];
		else if (bdevs.partitions[i].part_size > ext4_blkdev->part_size)
			ext4_blkdev = &bdevs.partitions[i];
		cnt++;
	}

	if (cnt == 0 || ext4_blkdev == NULL) {
		pr_err("no ext4 partition found\n");
		return -ENODEV;
	}

	if (cnt > 1)
		pr_warn("only one partition will support\n");

	memcpy(&vs->bdev, ext4_blkdev, sizeof(struct ext4_blockdev));
	r = ext4_device_register(&vs->bdev, "vd0");
	if (r) {
		pr_err("register ext4 partition fail\n");
		exit(r);
	}

	r = ext4_mount("vd0", "/", 0);
	if (r) {
		pr_err("mount ext4 partition fail\n");
		exit(r);
	}

	return run_ext4_server(vs);
}
