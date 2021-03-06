#ifndef __MINOS_HOOK_H__
#define __MINOS_HOOK_H__

#include <config/config.h>

typedef int (*hook_func_t)(void *item, void *contex);

enum hook_type {
	OS_HOOK_CREATE_TASK = 0,
	OS_HOOK_RELEASE_TASK,
	OS_HOOK_TASK_SWITCH,
	OS_HOOK_TASK_SWITCH_OUT,
	OS_HOOK_TASK_SWITCH_TO,
	OS_HOOK_ENTER_IRQ,

#ifdef CONFIG_VIRT
	OS_HOOK_EXIT_FROM_GUEST,
	OS_HOOK_ENTER_TO_GUEST,
	OS_HOOK_CREATE_VM,
	OS_HOOK_DESTROY_VM,
	OS_HOOK_SUSPEND_VM,
	OS_HOOK_RESUME_VM,
	OS_HOOK_SETUP_VM,
	OS_HOOK_VCPU_INIT,
#endif
	OS_HOOK_TYPE_UNKNOWN,
};

struct hook {
	hook_func_t fn;
	struct list_head list;
};

int do_hooks(void *item, void *context, enum hook_type type);
int register_hook(hook_func_t fn, enum hook_type type);

#endif
