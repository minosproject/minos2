/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
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

#include <minos/minos.h>
#include <minos/syscall.h>
#include <minos/time.h>
#include <minos/uaccess.h>

int sys_clock_gettime(int id, struct timespec __user *ts)
{
	unsigned long t;
	struct timespec __ts;

	switch (id) {
	case CLOCK_REALTIME:
	case CLOCK_MONOTONIC:
		t = get_current_time();
		__ts.tv_sec = t / 1000000000;
		__ts.tv_nsec = t - __ts.tv_sec;
		break;
	default:
		pr_err("unsupport clock id %d\n", id);
		return -ENOSYS;
	}

	if (copy_to_user(ts, &__ts, sizeof(struct timespec)) <= 0)
		return -EFAULT;

	return 0;
}

int sys_clock_nanosleep(int id, int flags, long time, long ns,
		struct timespec __user *rem)
{
	return 0;
}
