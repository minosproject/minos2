#include <sys/times.h>
#include "syscall.h"

clock_t times(struct tms *tms)
{
#if 0
	return __syscall(SYS_times, tms);
#endif
	return 0;
}
