#ifndef __MINOS_POLL_H__
#define __MINOS_POLL_H__

#include <minos/types.h>
#include <minos/kobject.h>

#define POLL_EV_IN		0
#define POLL_EV_KERNEL		1
#define POLL_EV_MAX		2

#define POLL_EV_TYPE_IN		(1 << POLL_EV_IN)
#define POLL_EV_TYPE_KERNEL	(1 << POLL_EV_KERNEL)
#define POLL_EV_MASK		(POLL_EV_TYPE_IN | POLL_EV_TYPE_KERNEL)

#define POLL_EVENT_DATA_SIZE	32

struct poll_hub {
	struct list_head event_list;
	spinlock_t lock;
	struct kobject kobj;
	struct task *task;
};

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

static inline int event_is_polled(struct poll_struct *ps, int event)
{
	return !!(ps->poll_event & event);
}

int poll_event_send_static(struct kobject *kobj,
			struct poll_event_kernel *evk);

int poll_event_send_with_data(struct kobject *kobj, int ev,
		handle_t handle, void *data, int len);

int poll_event_send(struct kobject *kobj, int ev, handle_t handle);

struct poll_event *alloc_poll_event(void);

#endif
