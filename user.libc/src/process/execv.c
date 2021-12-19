#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <minos/kobject.h>
#include <minos/proto.h>
#include <minos/types.h>

#include "pthread_impl.h"

static int setup_argv(struct execv_extra *extra, char *const argv[])
{
	int left = PAGE_SIZE - sizeof(struct execv_extra);
	int offset = 0, len, i;
	char *arg, *buf = extra->buf;

	if (argv == NULL)
		return 0;

	for (i = 0; i < 32; i++) {
		arg = argv[i];
		if (arg == NULL)
			break;

		len = strlen(arg) + 1;
		if (len > left)
			return -EINVAL;

		extra->argv[i] = offset;
		strncpy(buf, arg, len);
		offset += len;
		left -= len; 
	}

	extra->argc = i;
	return 0;
}

int execv(const char *path, char *const argv[])
{
	struct execv_extra *extra;
	struct proto proto;
	int ret = 0;

	if (strlen(path) >= FILENAME_MAX)
		return -ENAMETOOLONG;

	extra = malloc(PAGE_SIZE);
	if (!extra)
		return -ENOMEM;

	/*
	 * copy the filename and the additional info to the
	 * buf, then send to the server.
	 */
	memset((char *)extra, 0, PAGE_SIZE);
	if (setup_argv(extra, argv)) {
		ret = -EINVAL;
		goto out;
	}
	strcpy(extra->path, path);

	proto.proto_id = PROTO_EXECV;
	ret = kobject_write(self_handle(), &proto, PROTO_SIZE,
			extra, PAGE_SIZE, -1);
out:
	free(extra);
	return ret;
}
