#include "stdio_impl.h"
#include <string.h>

#include <minos/proto.h>
#include <minos/kobject.h>

size_t __stdio_write(FILE *f, const unsigned char *buf, size_t len)
{
	size_t rem = len + (f->wpos - f->wbase);
	size_t buf_rem = f->wend - f->wpos;
	size_t cnt, copy, write_size;
	unsigned char *wbuf = f->wpos;
	struct proto proto;
	size_t total = rem;

	proto.proto_id = PROTO_WRITE;
	copy = buf_rem > len ? len : buf_rem;
	write_size = (f->wpos - f->wbase) + copy;

	do {
		if (copy != 0)
			memcpy(wbuf, buf, copy);

		proto.write.len = write_size;
		proto.write.offset = wbuf - f->buf;
		cnt = kobject_write(f->fd, &proto, sizeof(struct proto),
				NULL, 0, -1);
		if (cnt < 0) {
			f->wpos = f->wbase = f->wend = 0;
			f->flags |= F_ERR;
			return 0;
		}

		total -= write_size;
		wbuf = f->buf;
		buf += copy;

		copy = total > f->buf_size ? f->buf_size : total;
		write_size = copy;
	} while (total > 0);

	f->wend = f->buf + f->buf_size;
	f->wpos = f->wbase = f->buf;

	return rem;
}
