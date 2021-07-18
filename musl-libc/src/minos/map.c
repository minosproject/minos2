#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"

int map(handle_t proc, handle_t pma, unsigned long base,
		size_t size, right_t right)
{
	return syscall(SYS_map, proc, pma, base, size, right);
}

int unmap(handle_t proc, handle_t pma, unsigned long base, size_t size)
{
	return syscall(SYS_unmap, proc, pma, base, size);
}
