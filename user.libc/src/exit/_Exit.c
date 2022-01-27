#include <stdlib.h>
#include "syscall.h"
#include "pthread_impl.h"

#include <minos/kobject.h>

_Noreturn void _Exit(int ec)
{
	for (;;) syscall(SYS_exitgroup, ec);
}
