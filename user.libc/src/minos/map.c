#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"

int sys_map(int proc, int pma, unsigned long base, size_t size, int right)
{
	return syscall(SYS_map, proc, pma, base, size, right);
}

int sys_unmap(int proc, int pma, unsigned long base, size_t size)
{
	return syscall(SYS_unmap, proc, pma, base, size);
}

unsigned long sys_mtrans(unsigned long virt)
{
	return syscall(SYS_mtrans, virt);
}
