#ifndef __MINOS_PROC_INFO_H__
#define __MINOS_PROC_INFO_H__

#include <minos/types.h>
#include <uapi/procinfo_uapi.h>

struct task;

struct ktask_stat *get_ktask_stat(int tid);
void release_ktask_stat(int tid);
struct uproc_info *get_uproc_info(int pid);
void init_ktask_stat(struct task *task);
void update_ktask_stat(struct task *task);
void get_and_init_ktask_stat(struct task *task);

#endif
