#ifndef __LIBC_THREAD_H__
#define __LIBC_THREAD_H__

#include <stdlib.h>

int create_thread(int (*fn)(void *), void *stack, int prio, int aff,
		int flags, void *tls, void *pdata);

#endif
