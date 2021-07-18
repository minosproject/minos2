#ifndef __MINOS_ENDPOINT_H__
#define __MINOS_ENDPOINT_H__

#include <minos/kobject.h>
#include <minos/list.h>
#include <minos/sem.h>

#define EP_READER		0
#define EP_WRITER		1
#define EP_NULL			2

#define EP_STAT_CLOSED		0
#define EP_STAT_OPENED		1

#define EP_NAME_SIZE		16
#define EP_RIGHT_MASK		(KOBJ_RIGHT_READ | KOBJ_RIGHT_WRITE | KOBJ_RIGHT_NONBLOCK)
#define EP_MAX_HANDLES		10
#define EP_MAX_HANDLES_SIZE	(EP_MAX_HANDLES * sizeof(handle_t))

struct task;

struct endpoint {
	pid_t owner[2];				// 0:READ 1:WRITE.
	int handles[2];				// handle in the owner process.
	int status[2];				// status for the reader and writer.

	struct kobject kobj;			// kobj for this endpoint.

	spinlock_t lock;			// spinlock to prevent below member.
	struct list_head pending_list;		// pending write task will list here.
	struct list_head processing_list;	// the task which has aready processing and waiting reply.
	long transaction_id;			// next transaction id for this endpoint.
	struct task *recv_task;			// which task is receiveing data from this endpoint.

	char name[EP_NAME_SIZE];		// the name of this endpoint.
};

struct endpoint_proto {
	unsigned long return_code;
	unsigned long data_addr;
	unsigned long data_size;
	unsigned long handle_addr;
	unsigned long handle_size;
	unsigned long flags;
	unsigned long timeout;
};

#endif
