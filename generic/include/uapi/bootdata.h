#ifndef __LIBMINOS_BOOTDATA_H__
#define __LIBMINOS_BOOTDATA_H__

#ifdef __KERNEL__
#include <minos/types.h>
#define ROOTSRV_USTACK_PAGES 4
#else
#include <inttypes.h>
#endif

#define CMDLINE_SIZE	512

#define BOOTDATA_MAGIC  0xe4b990e6958f

struct bootdata {
	uint64_t magic;
	uint64_t dtb_start;
	uint64_t dtb_end;
	uint64_t ramdisk_start;
	uint64_t ramdisk_end;
	uint64_t heap_start;
	uint64_t heap_end;
	uint64_t vmap_start;
	uint64_t vmap_end;
	int max_proc;
	int uproc_info_handle;
	int ktask_stat_handle;
};

#endif
