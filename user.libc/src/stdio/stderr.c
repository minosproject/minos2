#include "stdio_impl.h"

#undef stderr

static size_t __stderr_write(FILE *f, const unsigned char *buf, size_t len)
{
	return __stdout_write(f, buf, len);
}

static off_t __stderr_seek(FILE *f, off_t off, int whence)
{
	return 0;
}

static int __stderr_close(FILE *f)
{
	return __stdio_close(f);
}

hidden FILE __stderr_FILE = {
	.buf = NULL,
	.buf_size = 0,
	.fd = 3,
	.flags = F_PERM | F_NORD,
	.lbf = -1,
	.write = __stderr_write,
	.seek = __stderr_seek,
	.close = __stderr_close,
	.lock = -1,
};
FILE *const stderr = &__stderr_FILE;
FILE *volatile __stderr_used = &__stderr_FILE;
