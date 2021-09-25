#include "stdio_impl.h"

#undef stdin
#include <minos/kobject.h>

extern hidden int __stdio_close(FILE *f);

static size_t __stdin_read(FILE *f, unsigned char *buf, size_t len)
{
	size_t read_size;
	long ret;

	ret = kobject_read(f->fd, buf, len, &read_size, NULL, 0, NULL, 0);
	if (ret < 0) {
		f->flags |= F_ERR;
		return 0;
	}

	return read_size;
}

static off_t __stdin_seek(FILE *f, off_t off, int whence)
{
	return 0;
}

static int __stdin_close(FILE *f)
{
	return __stdio_close(f);
}

hidden FILE __stdin_FILE = {
	.buf = NULL,
	.buf_size = 0,
	.fd = 1,
	.flags = F_PERM | F_NOWR | F_STREAM,
	.read = __stdin_read,
	.seek = __stdin_seek,
	.close = __stdin_close,
	.lock = -1,
};
FILE *const stdin = &__stdin_FILE;
FILE *volatile __stdin_used = &__stdin_FILE;
