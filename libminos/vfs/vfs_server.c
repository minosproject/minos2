/*
 * Copyright (c) 2021 Min Le (lemin9538@163.com)
 * Copyright (c) 2021 上海网返科技
 */

/*
 * a vfs server can be dedicate thread, or running on
 * current thread.
 */

#define VFS_MAX_EVENTS 16

struct vfs_server_ops {
	int (*init)(void *pdata);
	int (*create)(struct file *file, char *fname, void *pdata);
	int (*open)(struct file *file, char *fname, int mode, int flag, void *pdata);
	ssize_t (*read)(struct file *file, void *buf, size_t size, void *pdata);
	ssize_t (*write)(struct file *file, void *buf, size_t size, void *pdata);
	int (*lseek)(struct file *file, off_t off, int whence, void *pdata);
};

struct vfs_server {
	struct file *root_file;
	void *data;
	int epfd;
	int new_thread;
	char buf[PAGE_SIZE];
};

static int vfs_server_add_file(struct vfs_server *vs, struct file *file)
{
	struct epoll_event event;
	int ret;

	event.events = EPOLL_IN | EPOLL_WCLOSE;
	event.data.ptr = file;
	ret = epoll_ctl(vs->epfd, EPOLL_CTL_ADD, file->handle, &event);
	if (ret) {
		pr_err("add file to vfs server failed\n");
		return ret;
	}

	return 0;
}

struct vfs_server *create_vfs_server(const char *name,
		struct vfs_server_ops *ops,
		void *data, int new_thread)
{
	struct vfs_server *vserver;
	int epfd, rfd;
	struct file *file;

	vserver = libc_zalloc(sizeof(struct vfs_server));
	if (!vserver) {
		pr_err("create vfs server failed\n");
		return NULL;
	}

	rfd = register_service("/", name, SRV_PORT, 0);
	if (rfd <= 0) {
		pr_err("create service for vfs server failed\n");
		libc_free(vserver);
		return NULL;
	}

	epfd = epoll_create(0);
	if (epfd <= 0) {
		pr_err("create epoll handle for vfs server failed\n");
		unregister_service(rfd);
		libc_free(vserver);
		return NULL;
	}

	vserver->data = data;
	vserver->epfd = epfd;

	file = &vserver->root_file;
	file->handle = rfd;
	file->root = 1;

	vfs_server_add_file(vserver, file);

	return vserver;
}

static int __handle_vfs_open_request(struct vfs_server *vs, struct file *file,
		struct proto *proto, struct file **new)
{
	struct file *new_file;
	int ret;

	if (file->type != DT_DIR)
		return -ENOTDIR;

	new_file = vs->ops->open(file, vs->buf, proto->open.flag,
			proto->open.mode, vs->data);
	if (!new_file) {
		pr_err("open new file failed %s\n", vs->buf);
		return ret;
	}

	ret = vfs_server_add_file(vs, new_file);
	if (ret) {
		pr_err("add new file failed %s\n");
		release_file(new_file);
	}

	*new = new_file;
	kobject_open(new_file->handle);

	return 0;
}

static int handle_vfs_open_request(struct vfs_server *vs,
			struct file *parent, struct proto *proto)
{
	struct file *file;
	int ret;

	ret = __handle_vfs_open_request(vs, parent, proto, &file);
	if (ret) {
		kobject_reply_errcode(parent->handle, proto->token, ret);
		return ret;
	}

	kobject_reply_handle(parent->handle, proto->token, file->handle, KR_WM);

	return 0;
}

static int handle_vfs_write_request(struct vfs_server *vs,
		struct file *file, struct proto *proto)
{
	ssize_t size;

	size = vs->ops->write(file, file->sbuf, proto->write.len);
	kobject_reply_errcode(file->handle, proto->token, size);

	return 0;
}

static int handle_vfs_read_request(struct vfs_server *vs,
		struct file *file, struct proto *proto)
{
	ssize_t size;

	size = vs->ops->read(file, file->sbuf, proto->read.len);
	kobject_reply_errcode(file->handle, proto->token, size);

	return 0;
}

static int handle_vfs_lseek_request(struct vfs_server *vs,
		struct file *file, struct proto *proto)
{
	return 0;
}

static int handle_vfs_ioctl_request(struct vfs_server *vs,
		struct file *file, struct proto *proto)
{
	return 0;
}

static int handle_vfs_getdent_request(struct vfs_server *vs,
		struct file *file, struct proto *proto)
{
	return 0;
}


static int handle_vfs_close_request(struct vfs_server *vs, struct file *file)
{
	/*
	 * close the file TBD
	 */
	return 0;
}

static int handle_vfs_in_request(struct vfs_server *vs, struct file *file)
{
	struct proto proto;
	int ret;

	ret = kobject_read_proto_with_string(file->handle, &proto, vs->buf, PAGE_SIZE, 0);
	if (ret)
		return ret;

	switch (proto->proto_id) {
	case PROTO_OPEN:
		ret = handle_vfs_open_request(vs, file, proto);
		break;
	case PROTO_READ:
		ret = handle_vfs_read_request(vs, file, proto);
		break;
	case PROTO_WRITE:
		ret = handle_vfs_write_request(vs, file, proto);
		break;
	case PROTO_GETDENT:
		ret = handle_vfs_getdent_request(vs, file, proto);
		break;
	case PROTO_LSEEK:
		ret = handle_vfs_lseek_request(vs, file, proto);
		break;
	case PROTO_IOCTL:
		ret = handle_vfs_ioctl_request(vs, file, proto);
		break;
	default:
		ret = -EINVAL;
		pr_err("unsupport vfs proto %d\n", proto->proto_id);
		break;
	}

	return ret;
}

static int handle_vfs_server_event(struct vfs_server *vs, struct epoll_event *event)
{
	struct file *file = event->data.ptr;
	struct proto proto;

	if (!file)
		return -ENOENT;

	if ((event->events != EPOLLIN) && (event->events != EPOLLWCLOSE))
		return -EPROTO;

	if (event->events == EPOLLWCLOSE)
		return handle_vfs_close_request(vs, file);
	else
		return handle_vfs_in_request(vs, file);
}

static void vfs_server_thread(void *data)
{
	struct vfs_server *vs = (struct vfs_server *)data;
	struct epoll_event events[VFS_MAX_EVENTS];
	int cnt, i;

	for (;;) {
		cnt = epoll_wait(vs->epfd, events, VFS_MAX_EVENTS, -1);
		if (cnt <= 0)
			continue;

		for (i = 0; i < cnt; i++)
			handle_vfs_server_event(vs, &events[i]);
	}
}

void run_vfs_server(struct vfs_server *vs)
{
	if (vs->new_thread) {
		vfs_server_thread(vs);
		return;
	}

	/*
	 * create a new thread to run the thread. TBD
	 */
}
