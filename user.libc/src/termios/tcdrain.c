#include <termios.h>
#include <sys/ioctl.h>
#include "syscall.h"

int tcdrain(int fd)
{
#if 0
	return syscall_cp(SYS_ioctl, fd, TCSBRK, 1);
#endif
	return 0;
}
