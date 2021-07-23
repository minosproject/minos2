#ifndef __MINOS_TASK_H__
#define __MINOS_TASK_H__

#include <minos/minos.h>
#include <minos/flag.h>
#include <config/config.h>
#include <minos/task_def.h>

#define to_task_info(task)	(&(task)->ti)

#ifdef CONFIG_TASK_RUN_TIME
#define TASK_RUN_TIME CONFIG_TASK_RUN_TIME
#else
#define TASK_RUN_TIME 100
#endif

static int inline task_is_idle(struct task *task)
{
	return (task->flags & TASK_FLAGS_IDLE);
}

static inline int get_task_tid(struct task *task)
{
	return task->tid;
}

static inline uint8_t get_task_prio(struct task *task)
{
	return task->prio;
}

static inline int task_is_suspend(struct task *task)
{
	return !!(task->stat & TASK_STAT_WAIT_EVENT);
}

static inline int task_is_running(struct task *task)
{
	return (task->stat == TASK_STAT_RUNNING);
}

static inline int task_is_vcpu(struct task *task)
{
	return (task->flags & TASK_FLAGS_VCPU);
}

static inline void task_set_resched(struct task *task)
{
	task->ti.flags |= TIF_NEED_RESCHED;
}

static inline void task_clear_resched(struct task *task)
{
	task->ti.flags &= ~TIF_NEED_RESCHED;
}

static inline int task_need_resched(struct task *task)
{
	return (task->ti.flags & TIF_NEED_RESCHED);
}

void release_task(struct task *task);
void do_release_task(struct task *task);
struct task *pid_to_task(int pid);
void os_for_all_task(void (*hdl)(struct task *task));
int kill(struct task *task, int signal);

struct task *get_task_by_tid(tid_t tid);
void clear_task_by_tid(tid_t tid);

struct task *create_task(char *name, task_func_t func,
		void *user_sp, int prio, int aff,
		unsigned long opt, void *arg);

#define task_lock(task)						\
	do {							\
		spin_lock(&task->s_lock);			\
	} while (0)

#define task_unlock(task)					\
	do {							\
		spin_unlock(&task->s_lock);			\
	} while (0)

#define task_lock_irqsave(task, flags)				\
	do {							\
		spin_lock_irqsave(&task->s_lock, flags);	\
	} while (0)

#define task_unlock_irqrestore(task, flags)			\
	do {							\
		spin_unlock_irqrestore(&task->s_lock, flags);	\
	} while (0)

#endif
