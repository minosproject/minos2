#ifndef __MINOS_HANDLE_H__
#define __MINOS_HANDLE_H__

#include <minos/types.h>
#include <minos/compiler.h>

struct kobject;

struct handle_desc {
	struct kobject *kobj;
	unsigned long right;
} __packed;

#define HANDLE_NULL	(-1)

#define NR_DESC_PER_PAGE (PAGE_SIZE / sizeof(struct handle_desc) - 1)
#define PROC_MAX_HANDLE	(NR_DESC_PER_PAGE * 128)

#define WRONG_HANDLE(handle)	\
	((handle == HANDLE_NULL) || (handle >= PROC_MAX_HANDLE))

int release_handle(handle_t handle);

handle_t __alloc_handle(struct process *proc, struct kobject *kobj, right_t right);

handle_t alloc_handle(struct kobject *kobj, right_t right);
int setup_handle(handle_t handle, struct kobject *kobj, right_t right);

int get_kobject_from_process(struct process *proc, handle_t handle,
			struct kobject **kobj, right_t *right);

int get_kobject(handle_t handle, struct kobject **kobj, right_t *right);

int put_kobject(struct kobject *kobj);

void deinit_proc_handles(struct process *proc);

int init_proc_handles(struct process *proc);

#endif
