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

static char *get_task_name(struct task_stat *kts, int i)
{
	if (kts[i].cmd[0] != 0)
		return kts[i].cmd;
	return kts[kts[i].root_tid].cmd;
}

static void print_process_info(int argc, char **argv, int proccnt,
		struct task_stat *kts)
{
	int i;

	/*
	 * TBD
	 */
	printf(" TID  PID CMD \n");
	for (i = 0; i < proccnt; i++) {
		if (kts[i].tid == 0)
			continue;

		printf("%4d %4d %s\n", kts[i].tid, kts[i].pid, get_task_name(kts, i));
	}
}

int main(int argc, char **argv)
{
	int32_t proccnt = sys_proccnt();
	int task_handle;
	struct task_stat *taskstat_addr;

	if (proccnt <= 0) {
		printf("get procnt failed %d\n", proccnt);
		return -ENOENT;
	}

	task_handle = sys_taskstat_handle();
	if (task_handle <= 0) {
		printf("can not get handles %d\n", task_handle);
		return -ENOENT;
	}

	if (kobject_mmap(task_handle, &taskstat_addr, NULL)) {
		printf("mmap taskstat mem failed\n");
		return -EFAULT;
	}

	/*
	 * print the process information and the task stat
	 */
	print_process_info(argc, argv, proccnt, taskstat_addr);

	return 0;
}
