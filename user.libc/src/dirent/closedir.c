#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include "__dirent.h"
#include "stdio_impl.h"

#include <minos/kobject.h>
#include <minos/proto.h>

int closedir(DIR *dir)
{
	int ret = kobject_close(dir->fd);
	free(dir);
	return ret;
}
