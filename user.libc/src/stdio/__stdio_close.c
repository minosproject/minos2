#include "stdio_impl.h"
#include "aio_impl.h"

#include <minos/kobject.h>

int __stdio_close(FILE *f)
{
	return kobject_close(f->fd);
}
