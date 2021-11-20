#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include "syscall.h"

static char __cwd[PATH_MAX];
DIR *__cdir = NULL;

char *getcwd(char *buf, size_t size)
{
        char tmp[buf ? 1 : PATH_MAX];

        if (!buf) {
                buf = tmp;
                size = sizeof tmp;
        } else if (!size) {
                errno = EINVAL;
                return 0;
        }

	strcpy(buf, __cwd);

        return buf == tmp ? strdup(buf) : buf;
}

DIR *getcdir(void)
{
	if (__cdir == NULL)
		__cdir = opendir(__cwd);
	return __cdir;
}

int chdir(const char *path)
{
	DIR *new;

	if ((strcmp(path, __cwd) == 0) && (__cdir != NULL))
		return 0;

	new = opendir(path);
	if (!new)
		return -ENOENT;

	strcpy(__cwd, path);
	if (__cdir)
		closedir(__cdir);
	__cdir = new;

	return 0;
}

hidden void __cwd_init(void)
{
	strcpy(__cwd, "/");
}
