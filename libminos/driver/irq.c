/*
 * Copyright (c) 2020 - 2021 Min Le (lemin9538@163.com)
 */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <minos/kobject.h>

int request_irq(int handle)
{
	return kobject_open(handle);
}
