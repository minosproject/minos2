#ifndef __MINOS_ASM_CURRENT_H__
#define __MINOS_ASM_CURRENT_H__

#include <minos/compiler.h>

static inline void *asm_get_current_task(void)
{
	register unsigned long __unused tsk asm ("x18");

	return (void *)tsk;
}

static inline void *asm_get_current_task_info(void)
{
	register unsigned long tsk_info asm ("x18");

	return (void *)tsk_info;
}

static inline void asm_set_current_task(void *task)
{
	register unsigned long __unused tsk asm ("x18") = (unsigned long)task;
}

#endif
