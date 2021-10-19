#ifndef __MINOS_PROTO_H__
#define __MINOS_PROTO_H__

#include <stdio.h>
#include <stdint.h>

enum {
	PROTO_IAMOK = 0,
	PROTO_ELF_INFO,
	PROTO_MMAP,
	PROTO_MUNMAP,
	PROTO_MPROTECT,
	PROTO_BRK,
	PROTO_EXECV,
	PROTO_PROC_END,
};

enum {
	PROTO_OPEN,
	PROTO_OPENAT,
	PROTO_READ,
	PROTO_WRITE,
	PROTO_IOCTL,
	PROTO_LSEEK,
	PROTO_GETDENTS,
	PROTO_REGISTER_SERVICE,
	PROTO_VFS_END,
};

enum {
	PROTO_ROOTFS_READY,
	PROTO_LOAD_DRIVER,
	PROTO_GET_MMIO,
	PROTO_GET_IRQ,
	PROTO_GET_DMA_CHANEL,
	PROTO_GET_IOMMU_SID,
};

#define PROC_PROTO_BASE PROTO_IAMOK
#define PROC_PROTO_END	PROTO_PROTO_EXECV
#define PROC_PROTO_CNT	(PROTO_PROC_END - PROTO_IAMOK)
#define PROC_PROTO_MAX	(PROTO_PROTO_EXECV - PROTO_IAMOK)

#define VFS_PROTO_BASE	PROTO_OPEN
#define VFS_PROTO_END	PROTO_GETDENT
#define VFS_PROTO_CNT	(PROTO_VFS_END - PROTO_OPEN)
#define VFS_PROTO_MAX	(PROTO_GETDENT - PROTO_OPEN)

struct proto_elf_info {
	int ret_code;
	uint64_t token;
	unsigned long entry;
	unsigned long elf_base;
	unsigned long elf_size;
};

struct proto_mprotect {
	void *addr;
	size_t len;
	int prot;
};

struct proto_brk {
	void *addr;
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
	char mode[4];
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
	int argv[32];
	int argc;
	int flags;
	char buf[0];
};

struct proto_devinfo {
	uint32_t key;
	int index;
};

struct proto_load_driver {
	char path[FILENAME_MAX];
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
		struct proto_elf_info elf_info;
		struct proto_brk brk;
		struct proto_register_service register_service;
		struct proto_devinfo devinfo;
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
