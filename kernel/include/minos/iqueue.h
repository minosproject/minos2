#ifndef __MINOS_IQUEUE_H__
#define __MINOS_IQUEUE_H__

#include <minos/list.h>

struct kobject;
struct task;

struct iqueue {
	int mutil_writer;
	int reader_stat;
	int writer_stat;
	spinlock_t lock;
	struct list_head pending_list;
	struct list_head processing_list;
	struct task *recv_task;
	struct kobject *kobj;
};

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
