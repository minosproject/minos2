#include <stdlib.h>
#include "syscall.h"

#include <minos/kobject.h>

_Noreturn void _Exit(int ec)
{
	while (1) kobject_ctl(0, KOBJ_PROCESS_EXIT, (unsigned long)ec);
}
