#ifndef __MINOS_PROTO_H__
#define __MINOS_PROTO_H__

#include <stdio.h>
#include <stdint.h>

enum {
	PROTO_IAMOK = 0x1024,
	PROTO_ELF_INFO,
	PROTO_MMAP,
	PROTO_MUNMAP,
	PROTO_MPROTECT,
	PROTO_BRK,
	PROTO_EXECV,
	PROTO_PROCCNT,
	PROTO_PROCINFO,
	PROTO_TASKSTAT,
	PROTO_WAITPID,
	PROTO_PANGU_END,
};

enum {
	PROTO_IAMOK_ID = 0,
	PROTO_ELF_INFO_ID,
	PROTO_MMAP_ID,
	PROTO_MUNMAP_ID,
	PROTO_MPROTECT_ID,
	PROTO_BRK_ID,
	PROTO_EXECV_ID,
	PROTO_PROCCNT_ID,
	PROTO_PROCINFO_ID,
	PROTO_TASKSTAT_ID,
	PROTO_WAITPID_ID,
	PROTO_PROC_ID_MAX,
};

enum {
	PROTO_OPEN = 0x2048,
	PROTO_OPENAT,
	PROTO_READ,
	PROTO_WRITE,
	PROTO_IOCTL,
	PROTO_LSEEK,
	PROTO_STAT,
	PROTO_ACCESS,
	PROTO_GETDENTS,
	PROTO_REGISTER_SERVICE,
	PROTO_VFS_END,
};

enum {
	PROTO_ROOTFS_READY = 0x4096,
	PROTO_LOAD_DRIVER,
	PROTO_GET_MMIO,
	PROTO_GET_IRQ,
	PROTO_GET_DMA_CHANEL,
	PROTO_GET_IOMMU_SID,
	PROTO_CHIYOU_END,
};

struct proto_waitpid {
	int pid;
	int options;
};

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

struct proto_access {
	int amode;
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
		struct proto_access access;
		struct proto_waitpid waitpid;
		struct proto_register_service register_service;
		struct proto_devinfo devinfo;
	};
};

struct service_info {
	int right;
	int type;
	char name[SERVICENAME_MAX];
};

#define PROTO_SIZE sizeof(struct proto)

int sys_read_proto_with_string(int handle, struct proto *proto,
		char *extra, size_t size, uint32_t timeout);

int sys_read_proto(int handle, struct proto *proto,
		char *extra, size_t size, uint32_t timeout);

long sys_send_proto(int handle, struct proto *proto);

long sys_send_proto_nonblock(int handle, struct proto *proto);

long sys_send_proto_timeout(int handle, struct proto *proto, uint32_t to);

long sys_send_proto_with_data(int handle, struct proto *proto,
		void *data, size_t dsz, uint32_t to);

void i_am_ok(void);

#endif
