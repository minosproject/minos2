#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"

handle_t grant(handle_t proc, handle_t handle, right_t right, int release)
{
	return syscall(SYS_grant, proc, handle, right, release);
}
