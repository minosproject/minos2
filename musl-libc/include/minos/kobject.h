#ifndef __LIBC_KOBJECT_H__
#define __LIBC_KOBJECT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdint.h>

#define KOBJ_RIGHT_NONE 0x0000
#define KOBJ_RIGHT_READ 0x0001
#define KOBJ_RIGHT_WRITE 0x0002
#define KOBJ_RIGHT_EXEC 0x0004
#define KOBJ_RIGHT_SHARED 0x0008
#define KOBJ_RIGHT_MMAP 0x0010
#define KOBJ_RIGHT_NONBLOCK 0x0020
#define KOBJ_RIGHT_CTL 0x0040
#define KOBJ_RIGHT_HEAP_SELFCTL 0x0080
#define KOBJ_RIGHT_GRANT 0x0100
#define KOBJ_RIGHT_POLL 0x0200

#define KOBJ_RIGHT_MASK 0x03ff

#define KOBJ_RIGHT_RW (KOBJ_RIGHT_READ | KOBJ_RIGHT_WRITE)
#define KOBJ_RIGHT_RO (KOBJ_RIGHT_READ)
#define KOBJ_RIGHT_RWX (KOBJ_RIGHT_RW | KOBJ_RIGHT_EXEC)

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
	KOBJ_PROCESS_GET_PID = 0x1000,
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
 * for poll_hub kobject
 */
enum {
	KOBJ_POLL_HUB_OP_BASE = 0x2000,
	KOBJ_POLL_OP_ADD,
	KOBJ_POLL_OP_DEL,
	KOBJ_POLL_OP_MOD,
};

/*
 * kobject related API.
 */
int kobject_open(int handle);

int kobject_connect(char *path, int right);

int kobject_close(int handle);

int kobject_create(char *name, int type, int right, int right_req,
		unsigned long data);

long kobject_read(int handle, void *data, size_t data_size,
		size_t *actual_data, void *extra, size_t extra_size,
		size_t *actual_extra, uint32_t timeout);

long kobject_write(int handle, void *data, size_t data_size,
		void *extra, size_t extra_size, uint32_t timeout);

int kobject_reply(int handle, long token, long err_code, int fd, int right);

void *kobject_mmap(int handle);

int kobject_unmap(int handle);

long kobject_ctl(int handle, int action, unsigned long data);

int grant(int proc, int handle, int right, int release);

#ifdef __cplusplus
}
#endif

#endif
