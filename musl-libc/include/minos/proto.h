#ifndef __MINOS_PROTO_H__
#define __MINOS_PROTO_H__

#include <stdio.h>

enum {
	PROTO_IAM_OK = 0,
	PROTO_MMAP,
	PROTO_MUNMAP,
	PROTO_MPROTECT,
	PROTO_EXECV,
	PROTO_OPEN,
	PROTO_READ,
	PROTO_WRITE,
	PROTO_IOCTL,
	PROTO_LSEEK,
	PROTO_MAX,
};

struct proto_mprotect {
	void *addr;
	size_t len;
	int prot;
};

struct proto_mmap {
	void *addr;
	size_t len;
	int prot;
	int flags;
	int fd;
	off_t offset;
};

struct proto_munmap {
	void *start;
	size_t len;
};

struct proto_open {
	int flags;
	int mode;
};

struct proto_read {
	size_t len;
	off_t offset;
};

struct proto_write {
	size_t len;
	off_t offset;
};

struct proto_lseek {
	off_t off;
	int whence;
};

struct open_extra {
	char path[FILENAME_MAX];
};

struct execv_extra {
	char path[FILENAME_MAX];
	char **argv;
	int argc;
	int padding;
	char buf[0];
};

struct proto {
	long token;
	int proto_id;
	int padding;
	union {
		struct proto_mmap mmap;
		struct proto_mprotect mprotect;
		struct proto_munmap munmap;
		struct proto_open open;
		struct proto_read read;
		struct proto_write write;
		struct proto_lseek lseek;
	};
};

#endif
