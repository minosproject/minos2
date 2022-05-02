#ifndef __MINOS_PROC_INFO_H__
#define __MINOS_PROC_INFO_H__

#include <minos/types.h>
#include <uapi/procinfo_uapi.h>

struct task;

void init_task_stat(struct task *task);
void release_task_stat(int tid);
void update_task_stat(struct task *task);
struct task_stat *get_task_stat(int tid);

#endif
