#ifndef __MINOS_SOCKET_H__
#define __MINOS_SOCKET_H__

#include <minos/kobject.h>

struct socket {
	int flags;
	void *data_addr;
	int pages;
	struct kobject kobj;
};

#endif
