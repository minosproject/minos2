#ifndef __MINOS_KOBJECT_H__
#define __MINOS_KOBJECT_H__

#include <minos/types.h>
#include <minos/compiler.h>
#include <config/config.h>

#include <minos/kobject_uapi.h>

struct task;
struct process;
struct ipc_msg;
struct kobject_ops;

struct poll_event_info {
	struct kobject *poller;
	unsigned long data;
};

struct poll_struct {
	int poll_event;
	struct poll_event_info infos[2];	// only support POLLIN and POLLOUT.
	spinlock_t lock;
};

/*
 * Kernel object is a object than can provide some ability
 * to user space thread.
 *
 * type : the type of this kobj defined as above.
 * ref  : reference count of this kernel object, when
 *        0 can be released.
 * rights : the original rights of this kernel object.
 * list : list all the kernel object for a task or global.
 */
struct kobject {
	int type;
	right_t right;
	atomic_t ref;
	struct poll_struct poll_struct;
	struct kobject_ops *ops;
	unsigned long data;
	struct list_head list;
};

#define KOBJ_PLACEHOLDER	(struct kobject *)(-1)

struct kobject_ops {
	long (*send)(struct kobject *kobj, void __user *data,
			size_t data_size, void __user *extra,
			size_t extra_size, uint32_t timeout);

	long (*recv)(struct kobject *kobj, void __user *data,
			size_t data_size, size_t *actual_data,
			void __user *extra, size_t extra_size,
			size_t *actual_extra, uint32_t timeout);

	void (*release)(struct kobject *kobj);

	int (*open)(struct kobject *kobj, handle_t handle, right_t right);

	int (*poll)(struct kobject *ksrc, struct kobject *kdst, int event, bool enable);

	int (*close)(struct kobject *kobj, right_t right);

	int (*reply)(struct kobject *kobj, right_t right, long token,
			long err_code, handle_t fd, right_t fd_right);

	void *(*mmap)(struct kobject *kobj, right_t right);

	int (*munmap)(struct kobject *kobj, right_t right);

	long (*ctl)(struct kobject *kobj, int req, unsigned long data);
};

typedef struct kobject *(*kobject_create_cb)( right_t right,
		right_t right_req, unsigned long data);

struct kobject_desc {
	char *name;
	int type;
	kobject_create_cb ops;
};

#define DEFINE_KOBJECT(kname, ktype, kops)	\
	static struct kobject_desc __kobject_##kname __used __section(".__kobject_desc") = { \
		.name = #kname,	\
		.type = ktype,	\
		.ops  = kops,	\
	}

void register_kobject_ops(struct kobject_ops *ops, int type);

int kobject_get(struct kobject *kobj);

int kobject_put(struct kobject *kobj);

void kobject_init(struct kobject *kobj, int type,
		right_t right, unsigned long data);

int kobject_close(struct kobject *kobj, right_t right);

struct kobject *kobject_create(int type, right_t right,
		right_t right_req, unsigned long data);

int kobject_poll(struct kobject *ksrc,
		struct kobject *dst, int event, int enable);

long kobject_recv(struct kobject *kobj, void __user *data,
		size_t data_size, size_t *actual_data,
		void __user *extra, size_t extra_size,
		size_t *actual_extra, uint32_t timeout);

long kobject_send(struct kobject *kobj, void __user *data,
		size_t data_size, void __user *extra,
		size_t extra_size, uint32_t timeout);

int kobject_reply(struct kobject *kobj, right_t right, unsigned long token,
		long err_code, handle_t fd, right_t fd_right);

int kobject_munmap(struct kobject *kobj, right_t right);

void *kobject_mmap(struct kobject *kobj, right_t right);

long kobject_ctl(struct kobject *kobj, right_t right,
		int req, unsigned long data);

int kobject_open(struct kobject *kobj, handle_t handle, right_t right);

handle_t kobject_send_handle(struct process *psrc, struct process *pdst,
		handle_t handle, right_t right_send);

#endif
