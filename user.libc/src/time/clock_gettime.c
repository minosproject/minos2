#include <time.h>
#include <errno.h>
#include <stdint.h>
#include "syscall.h"
#include "atomic.h"

int __clock_gettime(clockid_t clk, struct timespec *ts)
{
	return __syscall_ret(__syscall(SYS_clock_gettime, clk, ts));
}

weak_alias(__clock_gettime, clock_gettime);
