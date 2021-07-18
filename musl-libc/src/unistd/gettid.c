#include <unistd.h>

static int __gettid_dummy(void)
{
	return 0;
}

weak_alias(__gettid_dummy, __gettid);

int gettid(void)
{
        return __gettid();
}
