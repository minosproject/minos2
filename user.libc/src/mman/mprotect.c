#include <sys/mman.h>
#include "libc.h"
#include "syscall.h"
#include "pthread_impl.h"

#include <minos/proto.h>
#include <minos/kobject.h>

int __mprotect(void *addr, size_t len, int prot)
{
	struct proto proto;
	size_t start, end;

	start = (size_t)addr & -PAGE_SIZE;
	end = (size_t)((char *)addr + len + PAGE_SIZE-1) & -PAGE_SIZE;
	proto.proto_id = PROTO_MPROTECT;
	proto.mprotect.addr = (void *)start;
	proto.mprotect.len = end - start;
	proto.mprotect.prot = prot;

	return kobject_write(self_handle(), &proto,
			sizeof(struct proto), NULL, 0, -1);
}

weak_alias(__mprotect, mprotect);
