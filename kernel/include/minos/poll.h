#ifndef __MINOS_POLL_H__
#define __MINOS_POLL_H__

#include <minos/types.h>
#include <minos/kobject.h>

#define POLLIN 0x001
#define POLLPRI 0x002
#define POLLOUT 0x004
#define POLLRDNORM 0x040
#define POLLNVAL 0x020
#define POLLRDBAND 0x080
#define POLLWRNORM 0x100
#define POLLWRBAND 0x200
#define POLLMSG 0x400
#define POLLERR 0x008
#define POLLHUP 0x010
#define POLLRDHUP 0x2000
#define POLLEXCLUSIVE (1U<<28)
#define POLLWAKEUP (1U<<29)
#define POLLONESHOT (1U<<30)
#define POLLET (1U<<31)

#define POLLIN_WRITE	0x0
#define POLLIN_NOTIFY	0x1
#define POLLIN_PGF	0x2	// page fault
#define POLLIN_EXIT	0x3
#define POLLIN_IRQ	0x4

struct poll_hub {
	struct list_head event_list;
	spinlock_t lock;
	struct kobject kobj;
	struct task *task;
};

struct poll_data {
	void *ptr;
	int fd;
	int type;
	uint64_t data0;
	uint64_t data1;
	uint64_t data2;
};

struct poll_event {
	uint32_t events;
	struct poll_data data;
};

struct poll_event_kernel {
	struct poll_event event;
	struct list_head list;
	int release;
};

static inline int event_is_polled(struct poll_struct *ps, int event)
{
	return !!(ps->poll_event & event);
}

int poll_event_send_static(struct poll_struct *ps,
		struct poll_event_kernel *evk);

int poll_event_send(struct poll_struct *ps, int event, int type);

int poll_event_send_with_data(struct poll_struct *ps, int event, int type,
		uint64_t data0, uint64_t data1, uint64_t data2);

struct poll_event *alloc_poll_event(void);

#endif
