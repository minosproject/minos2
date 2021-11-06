#ifndef __MINOS_PROC_UAPI_INFO_H__
#define __MINOS_PROC_UAPI_INFO_H__

#define PROC_NAME_SIZE 256

struct uproc_info {
	int valid;
	int pid;
	int flags;
	unsigned long long pss;
	char cmd[PROC_NAME_SIZE];
};

struct ktask_stat {
	int valid;
	int pid;
	int tid;
	int state;
	int cpu;
	int cpu_usage;
	int prio;
	unsigned long long start_ns;
};

#endif
