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

struct poll_struct {
	unsigned long poll_event;
	struct kobject *poller;
	handle_t handle_poller;
	void *data;
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
 * owner : the process who create this kobject.
 * list : list all the kernel object for a task or global.
 */
struct kobject {
	int type;
	int flags;
	right_t right;
	pid_t owner;
	atomic_t ref;
	struct poll_struct poll_struct;
	struct kobject_ops *ops;
	unsigned long data;
	struct list_head list;
	union {
		struct list_head child;
		struct list_head parent;
	};
	const char *name;
};

#define KOBJ_FLAGS_INVISABLE	(1 << 0)	// kobject can be connected

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

	int (*poll)(struct kobject *ksrc, int event, int enable);

	int (*connect)(struct kobject *kobj, handle_t handle, right_t right);

	int (*close)(struct kobject *kobj, right_t right);

	int (*reply)(struct kobject *kobj, right_t right, long token,
			long err_code, handle_t fd, right_t fd_right);

	void *(*mmap)(struct kobject *kobj, right_t right);

	int (*munmap)(struct kobject *kobj, right_t right);

	long (*ctl)(struct kobject *kobj, int req, unsigned long data);
};

typedef struct kobject *(*kobject_create_cb)(char __user *name,
		right_t right, right_t right_req, unsigned long data);

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

void kobject_add(struct kobject *kobj);

void kobject_delete(struct kobject *kobj);

void kobject_init(struct kobject *kobj, pid_t owner, int type,
		int flags, right_t right, unsigned long data);

int kobject_close(struct kobject *kobj, right_t right);

int kobject_connect(char *name, right_t right);

struct kobject *kobject_create(char *name, int type, right_t right,
		right_t right_req, unsigned long data);

int kobject_poll(struct kobject *ksrc, int event, int enable);

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

int get_kobject_from_namespace(char *name, struct kobject **kobj, char **path);

struct kobject *get_kobject_by_name(struct kobject *root, const char *name);

void register_namespace(struct process *proc);

int kobject_open(struct kobject *kobj, handle_t handle, right_t right);

handle_t kobject_send_handle(struct process *psrc, struct process *pdst,
		handle_t handle, right_t right_send);
#endif
