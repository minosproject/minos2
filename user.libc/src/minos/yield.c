#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"

void yield(void)
{
	syscall(SYS_yield);
}
