#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"

int grant(int proc, int handle, int right)
{
	return syscall(SYS_grant, proc, handle, right);
}
