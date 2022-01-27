#include <termios.h>
#include <sys/ioctl.h>
#include "syscall.h"

int tcsetwinsize(int fd, const struct winsize *wsz)
{
#if 0
	return syscall(SYS_ioctl, fd, TIOCSWINSZ, wsz);
#endif
	return 0;
}
