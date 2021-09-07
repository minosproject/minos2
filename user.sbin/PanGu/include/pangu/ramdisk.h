#ifndef __PANGU_RAMDISK_H__
#define __PANGU_RAMDISK_H__

#include <inttypes.h>
#include <uapi/ramdisk.h>
#include <pangu/elf.h>

struct process;

int ramdisk_open(char *name, struct ramdisk_file *file);

int ramdisk_read(struct ramdisk_file *file, void *buf,
		size_t size, unsigned long offset);

int elf_init_ramdisk(struct elf_ctx *ctx, struct ramdisk_file *file);

int load_process_from_ramdisk(struct process *proc,
		struct elf_ctx *ctx, struct ramdisk_file *file);

#endif
