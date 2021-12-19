#include <sys/mman.h>
#include "syscall.h"

#include <minos/proto.h>
#include <minos/kobject.h>

#include "pthread_impl.h"

static void dummy(void) { }
weak_alias(dummy, __vm_wait);

int __munmap(void *start, size_t len)
{
	struct proto proto;

	proto.proto_id = PROTO_MUNMAP;
	proto.munmap.start = start;
	proto.munmap.len = len;
	__vm_wait();

	return __syscall_ret(kobject_write(self_handle(), &proto,
				sizeof(struct proto), NULL, 0, -1));
}

weak_alias(__munmap, munmap);
