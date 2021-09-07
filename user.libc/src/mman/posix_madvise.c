#define _GNU_SOURCE
#include <sys/mman.h>
#include "syscall.h"

int posix_madvise(void *addr, size_t len, int advice)
{
	return 0;
}
