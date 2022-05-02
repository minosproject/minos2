#ifndef __MINOS_PROC_UAPI_INFO_H__
#define __MINOS_PROC_UAPI_INFO_H__

#define PROC_NAME_SIZE 256

struct task_stat {
	int tid;
	int root_tid;
	int pid;
	int state;
	int cpu;
	int cpu_usage;
	int prio;
	unsigned long long start_ns;
	char cmd[PROC_NAME_SIZE];
};

#endif
