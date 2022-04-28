#ifndef __MINOS_EVENT_H__
#define __MINOS_EVENT_H__

#include <minos/preempt.h>
#include <minos/types.h>
#include <minos/spinlock.h>

#define OS_EVENT_OPT_NONE 0x0
#define OS_EVENT_OPT_BROADCAST 0x1

enum {
	OS_EVENT_TYPE_UNKNOWN = 0,
	OS_EVENT_TYPE_MBOX,
	OS_EVENT_TYPE_QUEUE,
	OS_EVENT_TYPE_SEM,
	OS_EVENT_TYPE_MUTEX,
	OS_EVENT_TYPE_FLAG,
	OS_EVENT_TYPE_NORMAL,

	OS_EVENT_TYPE_TIMER,
	OS_EVENT_TYPE_FUTEX,
	OS_EVENT_TYPE_ROOT_SERVICE,
	OS_EVENT_TYPE_IRQ,
	OS_EVENT_TYPE_POLL,

	OS_EVENT_TYPE_MAX
};

struct task;

struct event {
	int type;				/* event type */
	tid_t owner;				/* event owner the tid */
	uint32_t cnt;				/* event cnt */
	void *data;				/* event pdata for transfer */
	spinlock_t lock;			/* the lock of the event for smp */
	struct list_head wait_list;		/* non realtime task waitting list */
};

#define TO_EVENT(e)	(struct event *)(e)

uint32_t new_event_token(void);
void event_init(struct event *event, int type, void *pdata);
int remove_event_waiter(struct event *ev, struct task *task);
void event_pend_down(void);

void __wait_event(void *ev, int event, uint32_t to);
long wake(struct event *ev, long retcode);

long do_wait(void);

int __wake_up_event_waiter(struct event *ev, void *msg,
		int pend_state, int opt);

#define wake_up_event_waiter(ev, msg, pend_state, opt) \
	__wake_up_event_waiter(TO_EVENT(ev), msg, pend_state, opt)

#define wait_event(ev, condition, _to)			\
({							\
	__label__ __out;				\
	__label__ __out1;				\
	unsigned long flags;				\
	long __ret = 0;					\
	int need_wait = 1;				\
							\
	if ((condition) || ((_to) == 0))		\
		goto __out1;				\
							\
	if (is_task_need_stop(current)) {		\
		__ret = -EABORT;			\
		goto __out1;				\
 	}						\
							\
	spin_lock_irqsave(&(ev)->lock, flags);		\
	if (condition) {				\
		need_wait = 0;				\
		goto __out;				\
	}						\
	__wait_event(ev, OS_EVENT_TYPE_NORMAL, _to); 	\
__out:							\
	spin_unlock_irqrestore(&(ev)->lock, flags);	\
							\
	if (need_wait) {				\
		sched();				\
		__ret = current->pend_state;		\
		event_pend_down();			\
	}						\
__out1:	__ret;						\
})

long __wake(struct event *ev, int pend_state, long retcode);

#define wake(ev, retcode) __wake(ev, TASK_STATE_PEND_OK, retcode)
#define wake_abort(ev) __wake(ev, TASK_STATE_PEND_ABORT, -EABORT)
#define wake_timeout(ev) __wake(ev, TASK_STATE_PEND_TO, -ETIMEDOUT)

#endif
