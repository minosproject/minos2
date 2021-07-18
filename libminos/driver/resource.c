/*
 * Copyright (C) 2020 Min Le (lemin9538@gmail.com)
 */

#include <stdlib.h>
#include <minos/debug.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <ctype.h>

static int __get_resource_handles(char *compare, char *string,
		handle_t *handles, int cnt)
{
	int len = strlen(compare);
	char *tmp = string;
	char *str;
	int num = 0;

	if (strncmp(tmp, compare, len) != 0)
		return -EINVAL;

	tmp += len;
	while ((str = strsep(&tmp, ",")) != NULL) {
		if ((*str == 0) || (!isdigit(*str)))
			continue;

		handles[num++] = atoi(str);
		if (num >= cnt)
			break;
	}

	return num;
}

static int get_resource_handles(int argc, char **argv, char *comp,
		handle_t *handles, int cnt)
{
	int i;

	if (cnt <= 0)
		return -EINVAL;

	for (i = 0; i < argc; i++) {
		if (argv[i] == NULL)
			break;

		if (__get_resource_handles(comp, argv[i], handles, cnt) == cnt)
			return cnt;
	}

	return -ENOENT;
}

int get_irq_handles(int argc, char **argv, handle_t *handles, int cnt)
{
	return get_resource_handles(argc, argv, "irq@", handles, cnt);
}

int get_mmio_handles(int argc, char **argv, handle_t *handles, int cnt)
{
	return get_resource_handles(argc, argv, "mmio@", handles, cnt);
}

int get_dma_handles(int argc, char **argv, handle_t *handles, int cnt)
{
	return get_resource_handles(argc, argv, "dma@", handles, cnt);
}
