#ifndef __MINOS_MBOX_H__
#define __MINOS_MBOX_H__

#include <minos/event.h>

typedef struct event mbox_t;

#define DEFINE_MBOX(nam) \
	mbox_t name = { \
		.type = 0xff, \
	}

void *mbox_accept(mbox_t *m);
void *mbox_pend(mbox_t *m, uint32_t timeout);
int mbox_post(mbox_t *m, void *pmsg);
int mbox_post_opt(mbox_t *m, void *pmsg, int opt);
int mbox_is_pending(mbox_t *m);

static void inline mbox_init(mbox_t *mbox, void *pmsg)
{
	event_init(TO_EVENT(mbox), OS_EVENT_TYPE_MBOX, pmsg);
}

#endif
