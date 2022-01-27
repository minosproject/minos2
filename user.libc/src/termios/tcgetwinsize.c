#include <termios.h>
#include <sys/ioctl.h>
#include "syscall.h"

int tcgetwinsize(int fd, struct winsize *wsz)
{
#if 0
	return syscall(SYS_ioctl, fd, TIOCGWINSZ, wsz);
#endif
	return 0;
}
