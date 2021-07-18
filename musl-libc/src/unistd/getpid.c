#include <unistd.h>

static pid_t __getpid_dummy(void)
{
	return 0;
}

weak_alias(__getpid_dummy, __getpid);

pid_t getpid(void)
{
        return __getpid();
}
