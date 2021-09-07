#include <stdlib.h>
#include <stdint.h>

#include "stdio_impl.h"
#include <minos/kobject.h>

int create_thread(int (*fn)(void *), void *stack, int prio, int aff,
		int flags, void *tls, void *pdata)
{
#if 0
	struct thread_create_arg args;
	int handle;

	args.fn = fn;
	args.user_sp = stack;
	args.prio = prio;
	args.aff = aff;
	args.flags = flags;
	args.pdata = pdata;
	args.tls = tls;

	handle = kobject_create(NULL, KOBJ_TYPE_THREAD,
			KOBJ_RIGHT_CTL | KOBJ_RIGHT_READ,
			KOBJ_RIGHT_CTL | KOBJ_RIGHT_READ,
			(unsigned long)&args);
	if (handle < 0)
		return handle;

	kobject_ctl(handle, KOBJ_THREAD_OP_WAKEUP, 0);

	return handle;
#endif
	return 0;
}

