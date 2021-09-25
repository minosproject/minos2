#include "stdio_impl.h"
#include <sys/ioctl.h>

size_t __stdout_write(FILE *f, const unsigned char *buf, size_t len)
{
       size_t rem = len + (f->wpos - f->wbase);
       ssize_t cnt = 0;

       if (f->wpos - f->wbase > 0) {
               cnt = syscall(SYS_kobject_send, f->fd, f->wbase,
                               f->wpos - f->wbase, NULL, 0, 0);
               if (cnt < 0) {
                       f->wpos = f->wbase = f->wend = 0;
                       f->flags |= F_ERR;
                       return 0;
               }
       }

       if (len > 0) {
               cnt = syscall(SYS_kobject_send, f->fd, buf, len, NULL, 0, 0, 0);
               if (cnt < 0) {
                       f->wpos = f->wbase = f->wend = 0;
                       f->flags |= F_ERR;
                       return 0;
               }
       }

       f->wend = f->buf + f->buf_size;
       f->wpos = f->wbase = f->buf;

       return rem;
}
