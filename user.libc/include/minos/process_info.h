#ifndef __LIBC_PROCESS_INFO_H__
#define __LIBC_PROCESS_INFO_H__

#include <inttypes.h>

struct process_info {
	int pid;
	int state;
	uint64_t start_sec;
	char cmd[FILENAME_MAX];
};

#endif
