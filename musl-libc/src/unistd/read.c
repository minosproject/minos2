#include <unistd.h>
#include "syscall.h"
#include <string.h>

#include <minos/proto.h>
#include <minos/kobject.h>

ssize_t read(int fd, void *buf, size_t count)
{
	size_t left = count, read_size;
	ssize_t ret;
	struct proto proto;
	char *data;
	char *buffer = (char *)buf;

	data = (char *)kobject_ctl(fd, KOBJ_GET_MMAP_ADDR, 0);
	if (data == (char *)-1)
		return -EFAULT;

	proto.proto_id = PROTO_READ;

	while (left > 0) {
		read_size = left > BUFSIZ ? BUFSIZ : left;
		proto.read.len = read_size;

		ret = kobject_write(fd, &proto, sizeof(struct proto), NULL, 0, -1);
		if (ret <= 0)
			break;

		memcpy(buffer, data, ret);
		left -= ret;
		buffer += ret;
	}

	return (count - left);
}
