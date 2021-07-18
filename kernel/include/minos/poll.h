#ifndef __MINOS_POLL_H__
#define __MINOS_POLL_H__

#include <minos/types.h>

#define POLL_EV_IN		(1 << 0)
#define POLL_EV_OPEN		(1 << 1)
#define POLL_EV_CLOSE		(1 << 2)
#define POLL_EV_MASK		(POLL_EV_IN | POLL_EV_OPEN | POLL_EV_CLOSE)

#define POLL_EV_READER		(POLL_EV_IN)
#define POLL_EV_OWNER		(POLL_EV_OPEN | POLL_EV_CLOSE)

#define POLL_READER_BIT		(16)
#define POLL_OWNER_BIT		(17)

#define POLL_EVENT_DATA_SIZE	32

struct poll_event {
	int event;
	handle_t handle;
	unsigned char data[POLL_EVENT_DATA_SIZE];
};

struct poll_event_kernel {
	struct poll_event event;
	struct list_head list;
	int release;
};

struct poll_struct {
	unsigned long poll_event;
	tid_t tid_reader;
	tid_t tid_owner;
	handle_t handle_reader;
	handle_t handle_owner;
};

static inline int event_is_polled(struct poll_struct *ps, int event)
{
	return !!(ps->poll_event & event);
}

static inline tid_t poll_event_reader(struct poll_struct *ps)
{
	return ps->tid_reader;
}

int poll_event_send_static(tid_t tid, struct poll_event_kernel *evk);

int poll_event_send_with_data(tid_t tid, int ev,
		handle_t handle, void *data, int len);

int poll_event_send(tid_t tid, int ev, handle_t handle);

struct poll_event *alloc_poll_event(void);

int sys_poll_wait(struct poll_event __user *events,
		int max_event, uint32_t timeout);
#endif
