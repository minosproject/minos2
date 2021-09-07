#include "stdio_impl.h"
#include <sys/uio.h>
#include <string.h>

#include <minos/proto.h>
#include <minos/kobject.h>

size_t __stdio_read(FILE *f, unsigned char *buf, size_t len)
{
	/*
	 * read BUF_SIZE from the file, then copy to the buffer
	 */
	struct proto proto;
	size_t copy, rem, total = 0;
	long cnt;

	memset(&proto, 0, sizeof(struct proto));
	proto.proto_id = PROTO_READ;
	proto.read.len = f->buf_size;

	do {
		cnt = kobject_write(f->fd, &proto,
				sizeof(struct proto), NULL, 0, -1);
		if (cnt <= 0) {
			/*
			 * mark as end of file if needed.
			 */
			f->flags |= cnt ? F_ERR : F_EOF;
			if ((f->flags & F_EOF) && total < len)
				buf[total] = EOF;
			return 0;
		}

		copy = cnt > len ? len : cnt;
		memcpy(buf, f->buf, copy);
		buf += copy;
		len -= copy;
		total += copy;
		rem = cnt - copy;
	} while (len > 0);

	if (rem != 0) {
		f->rpos = f->buf + rem;
		f->rend = f->buf + cnt;
	}

	return total;
}
