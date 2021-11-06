/*
 * Copyright (C) 2021 Min Le (lemin9538@163.com)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <minos/procinfo.h>
#include <minos/proto.h>
#include <minos/kobject.h>

static void print_process_info(int argc, char **argv, int proccnt,
		struct uproc_info *upi, struct ktask_stat *kts)
{
	int i;

	/*
	 * TBD
	 */
	printf(" PID CMD \n");
	for (i = 0; i < proccnt; i++) {
		if (!upi[i].valid)
			continue;

		printf("%4d %s\n", upi[i].pid, upi[i].cmd);
	}
}

int main(int argc, char **argv)
{
	int32_t proccnt = sys_proccnt();
	int proc_handle, task_handle;
	struct uproc_info *procinfo_addr;
	struct ktask_stat *taskstat_addr;

	if (proccnt <= 0) {
		printf("get procnt failed %d\n", proccnt);
		return -ENOENT;
	}

	proc_handle = sys_procinfo_handle();
	task_handle = sys_taskstat_handle();
	if (proc_handle <= 0 || task_handle <= 0) {
		printf("can not get handles %d %d\n", proc_handle, task_handle);
		return -ENOENT;
	}

	if (kobject_mmap(proc_handle, &procinfo_addr, NULL)) {
		printf("mmap procinfo mem failed\n");
		return -EFAULT;
	}

	if (kobject_mmap(task_handle, &taskstat_addr, NULL)) {
		printf("mmap taskstat mem failed\n");
		return -EFAULT;
	}

	/*
	 * print the process information and the task stat
	 */
	print_process_info(argc, argv, proccnt, procinfo_addr, taskstat_addr);

	return 0;
}
