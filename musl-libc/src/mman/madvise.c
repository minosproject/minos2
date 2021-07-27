#include <sys/mman.h>
#include "syscall.h"

int __madvise(void *addr, size_t len, int advice)
{
	/*
	 * TBD.
	 */
	return 0;
}

weak_alias(__madvise, madvise);
