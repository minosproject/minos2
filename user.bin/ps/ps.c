/*
 * Copyright (C) 2021 Min Le (lemin9538@163.com)
 * Copyright (c) 2021 上海网返科技
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

static void print_process_info(struct process_info *pi)
{

}

int main(int argc, char **argv)
{
	struct process_info pi;
	struct dirent *dent;
	DIR *procdir;
	int fd, ret;

	procdir = opendir("/proc");
	if (!procdir)
		return -EIO;

	printf("PID TIME CMD\n")
	while (dent = readdir(procdir)) {
		fd = openat(procdir, dent->d_name, O_RDONLY);
		if (fd < 0) {
			printf("no such process %s\n", dent->d_name);
			continue;
		}

		ret = read(fd, &pi, sizeof(struct process_info));
		if (ret == sizeof(struct process_info))
			print_process_info(&pi);
		close(fd);
	}

	closedir(procdir);

	return 0;
}
