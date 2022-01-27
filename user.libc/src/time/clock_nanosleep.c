#include <time.h>
#include <errno.h>
#include "syscall.h"

#define IS32BIT(x) !((x)+0x80000000ULL>>32)
#define CLAMP(x) (int)(IS32BIT(x) ? (x) : 0x7fffffffU+((0ULL+(x))>>63))

int __clock_nanosleep(clockid_t clk, int flags, const struct timespec *req, struct timespec *rem)
{
	time_t s = req->tv_sec;
	long ns = req->tv_nsec;
	int r = -ENOSYS;

	if (clk == CLOCK_THREAD_CPUTIME_ID)
		return EINVAL;

	r = __syscall_cp(SYS_clock_nanosleep, clk, flags, s, ns, rem);

	return -r;
}

weak_alias(__clock_nanosleep, clock_nanosleep);
