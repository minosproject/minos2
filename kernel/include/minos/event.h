#ifndef __MINOS_EVENT_H__
#define __MINOS_EVENT_H__

#include <minos/preempt.h>
#include <minos/types.h>
#include <minos/spinlock.h>

#define OS_EVENT_OPT_NONE 0x0
#define OS_EVENT_OPT_BROADCAST 0x1

#define WAKEUP_ALL (-1)

enum {
	OS_EVENT_TYPE_NORMAL,
	OS_EVENT_TYPE_MBOX,
	OS_EVENT_TYPE_QUEUE,
	OS_EVENT_TYPE_SEM,
	OS_EVENT_TYPE_MUTEX,
	OS_EVENT_TYPE_FLAG,
	OS_EVENT_TYPE_FUTEX,
	OS_EVENT_TYPE_IRQ,
	OS_EVENT_TYPE_POLL,
	OS_EVENT_TYPE_MAX,
	OS_EVENT_TYPE_TIMER,
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
void event_pend_down(void);

void __wait_event(void *ev, int event, uint32_t to);
long wake(struct event *ev, long retcode);

long do_wait_event(struct event *ev);

int __wake_up_event_waiter(struct event *ev,
		long msg, int pend_state, int num);

struct task *wake_up_one_event_waiter(struct event *ev,
		long msg, int pend_state);

#define wake_up_event_waiter(ev, msg, pend_state, num) \
	__wake_up_event_waiter(TO_EVENT(ev), msg, pend_state, num)

/*
 * wait_event can only get the status of the event, can not get
 * the retcode from the waker, so the retcode of the waker need
 * store in otherwhere.
 */
#define wait_event(ev, condition, _to)				\
({								\
	__label__ __out1;					\
	unsigned long flags;					\
	long __ret = 0;						\
								\
	if (condition)						\
		goto __out1;					\
								\
	if (is_task_need_stop(current)) {			\
		__ret = -EABORT;				\
		goto __out1;					\
	}							\
								\
	spin_lock_irqsave(&(ev)->lock, flags);			\
	if (condition) {					\
		spin_unlock_irqrestore(&(ev)->lock, flags);	\
		goto __out1;					\
	} else if ((_to) == 0) {				\
		__ret = -EBUSY;					\
		spin_unlock_irqrestore(&(ev)->lock, flags);	\
		goto __out1;					\
	}							\
								\
	__wait_event(ev, OS_EVENT_TYPE_NORMAL, _to); 		\
	spin_unlock_irqrestore(&(ev)->lock, flags);		\
	__ret = do_wait_event(ev);				\
								\
__out1: __ret;							\
})

long __wake(struct event *ev, int pend_state, long retcode);

#define wake(ev, retcode) __wake(ev, TASK_STATE_PEND_OK, retcode)
#define wake_abort(ev) __wake(ev, TASK_STATE_PEND_ABORT, -EABORT)
#define wake_timeout(ev) __wake(ev, TASK_STATE_PEND_TO, -ETIMEDOUT)

#endif
