#ifndef __MINOS_KOBJECT_UAPI_H__
#define __MINOS_KOBJECT_UAPI_H__

#define KOBJ_RIGHT_NONE		0x0000		// do not have any right.
#define KOBJ_RIGHT_READ		0x0001		// can read this kobject, usually for IPC between two process.
#define KOBJ_RIGHT_WRITE	0x0002		// can write this kobject, usually for IPC between two process.
#define KOBJ_RIGHT_EXEC		0x0004		// can be exectued.
#define KOBJ_RIGHT_MMAP		0x0008		// can be mmaped to current process's memory space
#define KOBJ_RIGHT_CTL		0x0010		// can control the releated kobject
#define KOBJ_RIGHT_MASK		0x001f

#define KOBJ_RIGHT_SHARED	(1 << 16)	// can be shared, for example PMA
#define KOBJ_RIGHT_NONBLOCK	(1 << 17)	// read and write is non-blocked
#define KOBJ_RIGHT_HEAP_SELFCTL	(1 << 18)	// the process will allocation memory itself, for system process.
#define KOBJ_RIGHT_GRANT	(1 << 19)	// this kobject can be changed owner.

#define KOBJ_RIGHT_RW		(KOBJ_RIGHT_READ | KOBJ_RIGHT_WRITE)
#define KOBJ_RIGHT_RO		(KOBJ_RIGHT_READ)
#define KOBJ_RIGHT_RWX		(KOBJ_RIGHT_RW | KOBJ_RIGHT_EXEC)
#define KOBJ_RIGHT_ROOT		0xffffffff	// super right, only root sevice can have it.

enum {
	KOBJ_TYPE_NONE,
	KOBJ_TYPE_PROCESS,	// process, can be only created by root service
	KOBJ_TYPE_THREAD,	// thread, in kernel is a task, can be create by process.
	KOBJ_TYPE_NOTIFY,	// a port, which is a service hub
	KOBJ_TYPE_PMA,		// physical memory region, usually used to shared with each other.	
	KOBJ_TYPE_ENDPOINT,	// endpoint, an point to point ipc way
	KOBJ_TYPE_SOCKET,	// point to point ipc way.
	KOBJ_TYPE_VM,		// virtual machine, for Virtualization
	KOBJ_TYPE_VCPU,		// vcpu for vm
	KOBJ_TYPE_IRQ,		// irq for user-space driver
	KOBJ_TYPE_VIRQ,		// virq for vcpu process in user-space.
	KOBJ_TYPE_STDIO,	// dedicated for system debuging
	KOBJ_TYPE_POLL_HUB,	// hub for events need to send.
	KOBJ_TYPE_PORT,
	KOBJ_TYPE_MAX
};

enum {
	KOBJ_GET_MMAP_ADDR = 0x100,
};

/*
 * for process control
 */
enum {
	KOBJ_PROCESS_GET_PID = 0x1000,
	KOBJ_PROCESS_SETUP_SP,
	KOBJ_PROCESS_SETUP_REG0,
	KOBJ_PROCESS_WAKEUP,
	KOBJ_PROCESS_VA2PA,
	KOBJ_PROCESS_EXIT,
};

struct process_create_arg {
        unsigned long entry;
	unsigned long stack;
	int aff;
	int prio;
	unsigned long flags;
};

/*
 * for pma kobject
 */
enum {
	PMA_TYPE_NORMAL = 0,
	PMA_TYPE_MMIO,
	PMA_TYPE_DMA,
	PMA_TYPE_MAX
};

struct pma_create_arg {
	int cnt;
	int type;
	unsigned long start;
	unsigned long end;
};

/*
 * for kobject poll
 */
enum {
	KOBJ_POLL_HUB_OP_BASE = 0x2000,
	KOBJ_POLL_OP_ADD,
	KOBJ_POLL_OP_DEL,
	KOBJ_POLL_OP_MOD,
};

/*
 * for minos thread
 */
struct thread_create_arg {
	unsigned long func;
	void *user_sp;
	int prio;
	int aff;
	int flags;
	void *tls;
	void *pdata;
};

enum {
	KOBJ_THREAD_OP_BASE = 0x3000,
	KOBJ_THREAD_OP_WAKEUP,
};

#endif
