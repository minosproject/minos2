#ifndef __MINOS_IQUEUE_H__
#define __MINOS_IQUEUE_H__

#include <minos/list.h>
#include <minos/sem.h>
#include <minos/current.h>

struct kobject;
struct task;

#define IMSG_STATE_INIT 0
#define IMSG_STATE_IN_PROCESS 1
#define IMSG_STATE_ERROR 2

struct imsg {
	void *data;
	long token;
	long retcode;
	int state;
	int submit;
	struct list_head list;
	struct event ievent;
};

struct iqueue {
	int mutil_writer;
	int rstate;
	int wstate;

	spinlock_t lock;
	struct list_head pending_list;
	struct list_head processing_list;
	struct kobject *kobj;

	sem_t isem;
};

static void inline imsg_init(struct imsg *imsg, struct task *task)
{
	imsg->data = task;
	imsg->retcode = 0;
	imsg->token = new_event_token();
	imsg->state = IMSG_STATE_INIT;
	imsg->submit = 0;
	event_init(&imsg->ievent, OS_EVENT_TYPE_NORMAL, task);
}

long iqueue_recv(struct iqueue *iqueue, void __user *data,
		size_t data_size, size_t *actual_data, void __user *extra,
		size_t extra_size, size_t *actual_extra, uint32_t timeout);

long iqueue_send(struct iqueue *iqueue, void __user *data, size_t data_size,
		void __user *extra, size_t extra_size, uint32_t timeout);

int iqueue_reply(struct iqueue *iqueue, right_t right,
		long token, long errno, handle_t fd, right_t fd_right);

int iqueue_close(struct iqueue *iqueue, right_t right, struct process *proc);

void iqueue_init(struct iqueue *iq, int mutil_writer, struct kobject *kobj);

#endif
