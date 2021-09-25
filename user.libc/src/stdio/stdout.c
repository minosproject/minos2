#include "stdio_impl.h"

#undef stdout

hidden FILE __stdout_FILE = {
	.buf = NULL,
	.buf_size = 0,
	.fd = 2,
	.flags = F_PERM | F_NORD,
	.lbf = '\n',
	.write = __stdout_write,
	.seek = __stdio_seek,
	.close = __stdio_close,
	.lock = -1,
};
FILE *const stdout = &__stdout_FILE;
FILE *volatile __stdout_used = &__stdout_FILE;
