#include "stdio_impl.h"
#include <unistd.h>

#include <minos/proto.h>
#include <minos/kobject.h>

off_t __lseek(int fd, off_t off, int whence)
{
	struct proto proto;

	if (fd <= 3)
		return 0;

	proto.proto_id = PROTO_LSEEK;
	proto.lseek.off = off;
	proto.lseek.whence = whence;

	return kobject_write(fd, &proto, sizeof(struct proto), NULL, 0, -1);
}

off_t __stdio_seek(FILE *f, off_t off, int whence)
{
	return __lseek(f->fd, off, whence);
}
