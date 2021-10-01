/*
 * Copyright (c) 2021 Min Le (lemin9538@163.com)
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <minos/kobject.h>

int request_pma(size_t memsize)
{
	return kobject_create_pma(KR_RW | KR_S | KR_M, KR_RW | KR_S | KR_M, memsize);
}
