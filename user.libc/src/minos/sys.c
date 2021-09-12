/*
 * Copyright (c) 2020 - 2021 Min Le (lemin9538@163.com)
 */

#include <stdlib.h>
#include "libc.h"

void libc_set_rootfs_handle(int handle)
{
	libc.rootfs_handle = handle;
}
