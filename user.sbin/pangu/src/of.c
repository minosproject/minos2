/*
 * Copyright (C) 2020 Min Le (lemin9538@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/param.h>
#include <minos/debug.h>
#include <minos/compiler.h>

#include <libfdt/libfdt.h>

#include <pangu/kmalloc.h>
#include <pangu/bootarg.h>

void *dtb_address;

int of_init_bootargs(void)
{
	void *dtb = dtb_address;
	int node, len;
	const void *data = NULL;

	node = fdt_path_offset(dtb, "/chosen");
	if (node <= 0)
		return -ENOENT;

	data = fdt_getprop(dtb, node, "bootargs", &len);
	if (!data || (len == 0))
		return -ENOENT;

	bootargs_init(data, len);

	return 0;
}

int of_init(unsigned long dtb, unsigned long end)
{
	dtb_address = (void *)dtb;
	if (!dtb || fdt_check_header(dtb_address)) {
		pr_err("bad device tree address: %p\n", dtb_address);
		return -EFAULT;
	}

	return of_init_bootargs();
}
