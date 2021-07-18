#ifndef __MINOS_CURRENT_H__
#define __MINOS_CURRENT_H__

#include <minos/task_info.h>
#include <minos/task_def.h>
#include <minos/proc.h>

#define current			get_current_task()
#define current_proc		current->proc
#define current_task_info	get_current_task_info()
#define current_pid		current->pid
#define current_tid		current->tid

#endif
