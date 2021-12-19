#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include "syscall.h"
#include "pthread_impl.h"

#include <minos/proto.h>
#include <minos/kobject.h>

static void dummy(void) { }
weak_alias(dummy, __vm_wait);

#define UNIT SYSCALL_MMAP2_UNIT
#define OFF_MASK ((-0x2000ULL << (8*sizeof(syscall_arg_t)-1)) | (UNIT-1))

void *__mmap(void *start, size_t len, int prot, int flags, int fd, off_t off)
{
	struct proto proto;
	long ret;

	proto.proto_id = PROTO_MMAP;
	proto.mmap.addr = start;
	proto.mmap.len = len;
	proto.mmap.prot = prot;
	proto.mmap.flags = flags;
	proto.mmap.fd = fd;
	proto.mmap.offset = off;

	if (off & OFF_MASK) {
		errno = EINVAL;
		return MAP_FAILED;
	}
	if (len >= PTRDIFF_MAX) {
		errno = ENOMEM;
		return MAP_FAILED;
	}
	if (flags & MAP_FIXED) {
		__vm_wait();
	}

	ret = kobject_write(self_handle(), &proto, sizeof(struct proto), NULL, 0, -1);

	/* Fixup incorrect EPERM from kernel. */
	if (ret == -EPERM && !start && (flags&MAP_ANON) && !(flags&MAP_FIXED))
		ret = -ENOMEM;

	return (void *)__syscall_ret(ret);
}

weak_alias(__mmap, mmap);

weak_alias(mmap, mmap64);
