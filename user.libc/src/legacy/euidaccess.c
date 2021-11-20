#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>

int euidaccess(const char *filename, int amode)
{
	return 0;
}

weak_alias(euidaccess, eaccess);
