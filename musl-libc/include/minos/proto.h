#ifndef __MINOS_PROTO_H__
#define __MINOS_PROTO_H__

#include <stdio.h>
#include <stdint.h>

enum {
	PROTO_IAMOK = 0,
	PROTO_REGISTER_SERVICE,
	PROTO_MMAP,
	PROTO_MUNMAP,
	PROTO_MPROTECT,
	PROTO_EXECV,
	PROTO_OPEN,
	PROTO_OPENAT,
	PROTO_READ,
	PROTO_WRITE,
	PROTO_IOCTL,
	PROTO_LSEEK,
	PROTO_GETDENT,
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

struct proto_openat {
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

struct proto_register_service {
	int type;
	int flags;
	int source_off;
	int target_off;
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
		struct proto_open openat;
		struct proto_read read;
		struct proto_write write;
		struct proto_lseek lseek;
		struct proto_register_service register_service;
	};
};

struct proc_info {
	int pid;
	char name[PROCESSNAME_MAX];
};

struct service_info {
	int right;
	int type;
	char name[SERVICENAME_MAX];
};

#define PROTO_SIZE sizeof(struct proto)

int kobject_read_proto_with_string(int handle, struct proto *proto,
		char *extra, size_t size, uint32_t timeout);

int kobject_read_proto(int handle, struct proto *proto,
		char *extra, size_t size, uint32_t timeout);

void i_am_ok(void);

#endif
