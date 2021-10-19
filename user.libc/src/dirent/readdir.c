#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include "__dirent.h"
#include "syscall.h"

#include <minos/kobject.h>
#include <minos/proto.h>

typedef char dirstream_buf_alignment_check[1-2*(int)(
	offsetof(struct __dirstream, buf) % sizeof(off_t))];

static int __readdir(DIR *dir)
{
	struct proto proto;

	proto.proto_id = PROTO_GETDENTS;

	return kobject_write(dir->fd, &proto,
			sizeof(struct proto), NULL, 0, 5000);
}

struct dirent *readdir(DIR *dir)
{
	struct dirent *de;

	if (dir->buf_pos >= dir->buf_end) {
		int len = __readdir(dir);
		if (len <= 0) {
			if (len < 0 && len != -ENOENT) errno = -len;
			return 0;
		}
		dir->buf_end = len;
		dir->buf_pos = 0;
	}
	de = (void *)(dir->buf + dir->buf_pos);
	dir->buf_pos += de->d_reclen;
	dir->tell = de->d_off;
	return de;
}

weak_alias(readdir, readdir64);
