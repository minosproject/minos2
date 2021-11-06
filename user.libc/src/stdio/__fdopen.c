#include "stdio_impl.h"
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "libc.h"

#include <minos/kobject.h>
#include <minos/proto.h>

FILE *__fdopen(int fd, int flags)
{
	FILE *f;
	struct winsize wsz;

	/* Allocate FILE+buffer or fail */
	if (!(f=malloc(sizeof *f + UNGET))) return 0;

	/* Zero-fill only the struct, not the buffer */
	memset(f, 0, sizeof *f);

#if 0
	/* Apply close-on-exec flag */
	if (strchr(mode, 'e')) __syscall(SYS_fcntl, fd, F_SETFD, FD_CLOEXEC);
#endif

	if (kobject_mmap(fd, &f->buf, NULL)) {
		free(f);
		return 0;
	}

	f->flags = flags;
	f->fd = fd;
	f->buf_size = BUFSIZ;

	/* Activate line buffered mode for terminals */
	f->lbf = EOF;

#if 0
	/* Is this file is a tty device ? */
	if (!(f->flags & F_NOWR) && !__syscall(SYS_ioctl, fd, TIOCGWINSZ, &wsz))
		f->lbf = '\n';
#endif

	/* Initialize op ptrs. No problem if some are unneeded. */
	f->read = __stdio_read;
	f->write = __stdio_write;
	f->seek = __stdio_seek;
	f->close = __stdio_close;

	if (!libc.threaded) f->lock = -1;

	/* Add new FILE to open file list */
	return __ofl_add(f);
}

FILE *fdopen(int fd, const char *mode)
{
	/* Check for valid initial mode character */
	if (!strchr("rwa", *mode)) {
		errno = EINVAL;
		return 0;
	}

	return __fdopen(fd, __fmodeflags(mode));
}
