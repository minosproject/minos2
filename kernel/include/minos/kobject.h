#ifndef __MINOS_KOBJECT_H__
#define __MINOS_KOBJECT_H__

#include <minos/types.h>
#include <minos/compiler.h>
#include <config/config.h>
#include <minos/poll.h>

#define KOBJ_RIGHT_NONE		0x0000		// do not have any right.
#define KOBJ_RIGHT_READ		0x0001		// can read this kobject, usually for IPC between two process.
#define KOBJ_RIGHT_WRITE	0x0002		// can write this kobject, usually for IPC between two process.
#define KOBJ_RIGHT_EXEC		0x0004		// can be exectued.
#define KOBJ_RIGHT_SHARED	0x0008		// can be shared, for example PMA
#define KOBJ_RIGHT_MMAP		0x0010		// can be mmaped to current process's memory space
#define KOBJ_RIGHT_NONBLOCK	0x0020		// read and write is non-blocked
#define KOBJ_RIGHT_CTL		0x0040		// can control the releated kobject
#define KOBJ_RIGHT_HEAP_SELFCTL	0x0080		// the process will allocation memory itself, for system process.
#define KOBJ_RIGHT_GRANT	0x0100		// this kobject can be changed owner.
#define KOBJ_RIGHT_LISTEN	0x0200		// this kobject cab be listened

#define KOBJ_RIGHT_MASK		0x03ff

#define KOBJ_RIGHT_RW		(KOBJ_RIGHT_READ | KOBJ_RIGHT_WRITE)
#define KOBJ_RIGHT_RO		(KOBJ_RIGHT_READ)
#define KOBJ_RIGHT_RWX		(KOBJ_RIGHT_RW | KOBJ_RIGHT_EXEC)
#define KOBJ_RIGHT_ROOT		0xffff		// super right, only root sevice can have it.

#define KOBJ_STATE_OPENED	(1UL << 31)

enum {
	KOBJ_TYPE_NONE,
	KOBJ_TYPE_PROCESS,	// process, can be only created by root service
	KOBJ_TYPE_THREAD,	// thread, in kernel is a task, can be create by process.
	KOBJ_TYPE_PORT,		// a port, which is a service hub
	KOBJ_TYPE_PMA,		// physical memory region, usually used to shared with each other.	
	KOBJ_TYPE_ENDPOINT,	// endpoint, an point to point ipc way
	KOBJ_TYPE_SOCKET,	// point to point ipc way.
	KOBJ_TYPE_VM,		// virtual machine, for Virtualization
	KOBJ_TYPE_VCPU,		// vcpu for vm
	KOBJ_TYPE_IRQ,		// irq for user-space driver
	KOBJ_TYPE_VIRQ,		// virq for vcpu process in user-space.
	KOBJ_TYPE_STDIO,	// dedicated for system debuging
	KOBJ_TYPE_MAX
};

#define KOBJ_FLAGS_INVISABLE	(1 << 1)	// kobject can be connected
#define KOBJ_FLAGS_NEED_REPLY	(1 << 5)	// kobject need a reply after recv.

struct task;
struct process;
struct ipc_msg;
struct kobject_ops;

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

#define KOBJ_PLACEHOLDER	(struct kobject *)(-1)

struct kobject_ops {
	ssize_t (*send)(struct kobject *kobj, void __user *data,
			size_t data_size, void __user *extra,
			size_t extra_size, uint32_t timeout);

	ssize_t (*recv)(struct kobject *kobj, void __user *data,
			size_t data_size, void __user *extra,
			size_t extra_size, uint32_t timeout);

	void (*release)(struct kobject *kobj);

	int (*open)(struct kobject *kobj, handle_t handle, right_t right);

	int (*listen)(struct kobject *kobj, handle_t handle, int event);

	int (*connect)(struct kobject *kobj, handle_t handle, right_t right);

	int (*close)(struct kobject *kobj, right_t right);

	int (*reply)(struct kobject *kobj, right_t right,
			long token, long err_code);

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

int kobject_destroy(struct kobject *kobj, right_t right);

int kobject_listen(struct kobject *kobj, handle_t handle,
		right_t right, int event);

ssize_t kobject_recv(struct kobject *kobj,
		void __user *data, size_t data_size,
		void __user *extra, size_t extra_size,
		uint32_t timeout);

ssize_t kobject_send(struct kobject *kobj,
		void __user *data, size_t data_size,
		void __user *extra, size_t extra_size,
		uint32_t timeout);

int kobject_reply(struct kobject *kobj, right_t right,
			unsigned long token, long err_code);

int kobject_munmap(struct kobject *kobj, right_t right);

void *kobject_mmap(struct kobject *kobj, right_t right);

long kobject_ctl(struct kobject *kobj, right_t right,
		int req, unsigned long data);

int get_kobject_from_namespace(char *name, struct kobject **kobj, char **path);

struct kobject *get_kobject_by_name(struct kobject *root, const char *name);

void register_namespace(struct process *proc);

int kobject_check_right(struct kobject *kobj, right_t right, right_t request);

int kobject_open(struct kobject *kobj, handle_t handle, right_t right);

#endif
