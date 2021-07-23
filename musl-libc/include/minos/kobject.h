#ifndef __LIBC_KOBJECT_H__
#define __LIBC_KOBJECT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdint.h>

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

enum {
	KOBJ_TYPE_NONE,
	KOBJ_TYPE_PROCESS,
	KOBJ_TYPE_THREAD,
	KOBJ_TYPE_PORT,
	KOBJ_TYPE_PMA,
	KOBJ_TYPE_ENDPOINT,
	KOBJ_TYPE_SOCKET,
	KOBJ_TYPE_VM,
	KOBJ_TYPE_VCPU,
	KOBJ_TYPE_IRQ,
	KOBJ_TYPE_VIRQ,
	KOBJ_TYPE_STDIO,
	KOBJ_TYPE_POLL_HUB,
	KOBJ_TYPE_MAX
};

/*
 * for process control
 */
enum {
	KOBJ_PROCESS_GET_PID = 0x100,
	KOBJ_PROCESS_SETUP_SP,
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
 * for thread kobject
 */
struct thread_create_arg {
	unsigned long func;
	void *user_sp;
	int prio;
	int aff;
	unsigned long flags;
};

/*
 * kobject related API.
 */
int kobject_connect(char *path, right_t right);

int kobject_close(handle_t handle);

int kobject_listen(handle_t to, handle_t from,
		int event, unsigned long data);

handle_t kobject_create(char *name, int type, int right,
		unsigned long flags, unsigned long data);

ssize_t kobject_read(handle_t handle, void *data, size_t data_size,
		void *extra, size_t extra_size, uint32_t timeout);

ssize_t kobject_write(handle_t handle, void *data, size_t data_size,
		void *extra, size_t extra_size, uint32_t timeout);

int kobject_reply(handle_t handle, long token, int err_code);

void *kobject_mmap(handle_t handle);

int kobject_unmap(handle_t handle);

long kobject_ctl(handle_t handle, int action, unsigned long data);

int kobject_open(handle_t handle);

handle_t grant(handle_t proc, handle_t handle, right_t right, int release);

#ifdef __cplusplus
}
#endif

#endif
