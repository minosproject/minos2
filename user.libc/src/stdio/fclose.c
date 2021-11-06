#include "stdio_impl.h"
#include <stdlib.h>

static void dummy(FILE *f) { }
weak_alias(dummy, __unlist_locked_file);

static int __fclose(FILE *f, int del)
{
	int r;
	
	FLOCK(f);
	r = fflush(f);
	r |= f->close(f);
	FUNLOCK(f);

	/* Past this point, f is closed and any further explict access
	 * to it is undefined. However, it still exists as an entry in
	 * the open file list and possibly in the thread's locked files
	 * list, if it was closed while explicitly locked. Functions
	 * which process these lists must tolerate dead FILE objects
	 * (which necessarily have inactive buffer pointers) without
	 * producing any side effects. */

	if (f->flags & F_PERM) return r;

	/*
	 * delete it from the open file list. TBD
	 */
	__unlist_locked_file(f);
	if (del)
		__ofl_del(f);

	free(f->getln_buf);
	free(f);

	return r;
}

int fclose(FILE *f)
{
	return __fclose(f, 1);
}

int fclose_fd(int fd)
{
	FILE *file = __ofl_del_fd(fd);
	if (!file)
		return -ENOENT;

	return __fclose(file, 0);
}
