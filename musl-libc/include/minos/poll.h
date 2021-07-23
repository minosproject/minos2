#ifndef __LIBC_MINOS_POLL_H__
#define __LIBC_MINOS_POLL_H__

#include <inttypes.h>

#define POLL_EV_IN		0
#define POLL_EV_KERNEL		1
#define POLL_EV_MAX		2

#define POLL_EVENT_DATA_SIZE	32

struct poll_event {
	int event;
	int handle;
	unsigned char data[POLL_EVENT_DATA_SIZE];
};

int poll_wait(int handke, struct poll_event *events,
		int max_event, uint32_t timeout);

#endif
