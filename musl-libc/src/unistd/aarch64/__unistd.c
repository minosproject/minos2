#include <unistd.h>

pid_t __getpid(void)
{
	unsigned long v;
	__asm__ volatile ("mrs %0, tpidrro_el0" : "=r" (v));
	return (pid_t)(v >> 32);
}

int __gettid(void)
{
	unsigned long v;
	__asm__ volatile ("mrs %0, tpidrro_el0" : "=r" (v));
	return (int)(v & 0xffffffff);
}
