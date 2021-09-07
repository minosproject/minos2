#include "stdio_impl.h"

#undef stdin

extern hidden int __stdio_close(FILE *f);

static size_t __stdin_read(FILE *f, unsigned char *buf, size_t len)
{
	return 0;
}

static off_t __stdin_seek(FILE *f, off_t off, int whence)
{
	return 0;
}

static int __stdin_close(FILE *f)
{
	return __stdio_close(f);
}

static unsigned char buf[BUFSIZ+UNGET];
hidden FILE __stdin_FILE = {
	.buf = buf+UNGET,
	.buf_size = sizeof buf-UNGET,
	.fd = 1,
	.flags = F_PERM | F_NOWR,
	.read = __stdin_read,
	.seek = __stdin_seek,
	.close = __stdin_close,
	.lock = -1,
};
FILE *const stdin = &__stdin_FILE;
FILE *volatile __stdin_used = &__stdin_FILE;
