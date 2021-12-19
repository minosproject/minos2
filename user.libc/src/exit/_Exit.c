#include <stdlib.h>
#include "syscall.h"
#include "pthread_impl.h"

#include <minos/kobject.h>

_Noreturn void _Exit(int ec)
{
	while (1)
		kobject_close(self_handle());
}
