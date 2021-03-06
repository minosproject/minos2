#ifndef __MINOS_POLL_H__
#define __MINOS_POLL_H__

#include <minos/types.h>
#include <uspace/kobject.h>

#define POLLIN 0x001
#define POLLOUT 0x002
#define POLLROPEN 0X004
#define POLLRCLOSE 0x008
#define POLLWOPEN 0x010
#define POLLWCLOSE 0x020
#define POLLKERNEL 0x040

enum {
	EV_IN = 0,
	EV_OUT,
	EV_ROPEN,
	EV_RCLOSE,
	EV_WOPEN,
	EV_WCLOSE,
	EV_KERNEL,
	EV_MAX,
};

#define POLL_EVENT_MASK \
	(POLLIN | POLLOUT | POLLROPEN | POLLRCLOSE | \
	 POLLWOPEN | POLLWCLOSE | POLLKERNEL)

#define POLL_READ_RIGHT_EVENT \
	(POLLIN | POLLWOPEN | POLLWCLOSE | POLLKERNEL)

#define POLL_WRITE_RIGHT_EVENT \
	(POLLOUT | POLLROPEN | POLLRCLOSE)

/*
 * kernel events - which sended by kernel which
 * happend on the kobject.
 */
#define POLL_KEV_NULL 0x0
#define POLL_KEV_PAGE_FAULT 0x1
#define POLL_KEV_PROCESS_EXIT 0x2

struct poll_hub {
	struct list_head event_list;
	spinlock_t lock;
	struct kobject kobj;
	struct event event;
};

struct pevent_item {
	struct poll_hub *poller;
	unsigned long data;
	struct pevent_item *next;
};

struct poll_struct {
	struct pevent_item *pevents[EV_MAX];
};

struct poll_data {
	union {
		void *ptr;
		unsigned long pdata;
	};
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

static inline int event_is_polled(struct poll_struct *ps, int ev)
{
	return (ps && (ps->pevents[ev]));
}

int poll_event_send_static(struct pevent_item *pi, struct poll_event_kernel *evk);

int poll_event_send(struct poll_struct *ps, int ev);

int poll_event_send_with_data(struct poll_struct *ps, int event, int type,
		uint64_t data0, uint64_t data1, uint64_t data2);

struct poll_event *alloc_poll_event(void);

void release_poll_struct(struct kobject *kobj);

#endif
