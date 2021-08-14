/*
 * Copyright (C) 2019 Min Le (lemin9538@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <minos/minos.h>
#include <minos/sched.h>
#include <minos/mm.h>
#include <minos/atomic.h>
#include <minos/task.h>

static DEFINE_SPIN_LOCK(tid_lock);
static DECLARE_BITMAP(tid_map, OS_NR_TASKS);
struct task *os_task_table[OS_NR_TASKS];

static atomic_t os_task_nr;

/* idle task needed be static defined */
struct task idle_tasks[NR_CPUS];
static DEFINE_PER_CPU(struct task *, idle_task);

#define TASK_INFO_INIT(__ti, task) 		\
	do {					\
		(__ti)->task = task;		\
		(__ti)->preempt_count = 0; 	\
		(__ti)->flags = 0;		\
	} while (0)

static int alloc_tid(void)
{
	int tid = -1;

	spin_lock(&tid_lock);

	tid = find_next_zero_bit(tid_map, OS_NR_TASKS, 0);
	if (tid >= OS_NR_TASKS)
		tid = -1;
	else
		set_bit(tid, tid_map);

	spin_unlock(&tid_lock);

	return tid;
}

static int request_tid(int tid)
{
	BUG_ON((tid <= 0) || (tid >= OS_NR_TASKS), "no such tid %d\n", tid);
	return !test_and_set_bit(tid, tid_map);
}

static void release_tid(int tid)
{
	ASSERT((tid < OS_NR_TASKS) && (tid > 0));
	os_task_table[tid] = NULL;
	clear_bit(tid, tid_map);
}

struct task *get_task_by_tid(tid_t tid)
{
	ASSERT((tid < OS_NR_TASKS) && (tid > 0));
	return  os_task_table[tid];
}

void clear_task_by_tid(tid_t tid)
{
	ASSERT((tid < OS_NR_TASKS) && (tid > 0));
	os_task_table[tid] = NULL;
	wmb();
}

static void task_timeout_handler(unsigned long data)
{
	struct task *task = (struct task *)data;

	wake_up_timeout(task);
	set_need_resched();
}

static void task_init(struct task *task, char *name,
		void *stack, uint32_t stk_size, void *arg,
		int prio, int tid, int aff, unsigned long opt)
{
	int cpu;

	/*
	 * idle task is setup by create_idle task, skip
	 * to setup the stack information of idle task, by
	 * default the kernel stack will set to stack top.
	 */
	if (!(opt & TASK_FLAGS_IDLE)) {
		task->stack_bottom = stack;
		task->stack_top = stack + stk_size;
		task->stack_base = task->stack_top;

		TASK_INFO_INIT(&task->ti, task);
	}

	cpu = (aff == TASK_AFF_ANY) ? 0 : aff;

	task->cpu = -1;
	task->pdata = arg;
	task->tid = tid;
	task->prio = prio;
	task->pend_stat = 0;
	task->flags = opt;
	task->pdata = arg;
	task->affinity = aff;
	task->run_time = TASK_RUN_TIME;
	spin_lock_init(&task->s_lock);


	if ((task->flags & TASK_FLAGS_VCPU) ||
			(task->flags & TASK_FLAGS_NO_AUTO_START)) {
		task->stat = TASK_STAT_WAIT_EVENT;
		task->wait_type = TASK_EVENT_STARTUP;
		task->cpu = -1;
	} else {
		task->stat = TASK_STAT_RUNNING;
		task->cpu = cpu;
	}

	/*
	 * driver task can not be preempt once it ran
	 * util it drop the cpu by itself.
	 */
	if (task->flags & TASK_FLAGS_DRV)
		task->ti.flags |= __TIF_DONOT_PREEMPT;

	init_timer_on_cpu(&task->delay_timer, cpu);
	task->delay_timer.function = task_timeout_handler;
	task->delay_timer.data = (unsigned long)task;

	if (name)
		strncpy(task->name, name, MIN(strlen(name), TASK_NAME_SIZE));
	else
		task->name[0] = '\0';
}

static struct task *do_create_task(char *name,
				  task_func_t func,
				  uint32_t ssize,
				  int prio,
				  int tid,
				  int aff,
				  unsigned long opt,
				  void *arg)
{
	size_t stk_size = PAGE_BALIGN(ssize);
	struct task *task;
	void *stack = NULL;

	/*
	 * allocate the task's kernel stack
	 */
	task = zalloc(sizeof(struct task));
	if (!task) {
		pr_err("no more memory for task\n");
		return NULL;
	}

	stack = get_free_pages(PAGE_NR(stk_size), GFP_KERNEL);
	if (!stack) {
		pr_err("no more memory for task stack\n");
		free(task);
		return NULL;
	}

	/* store this task to the task table */
	os_task_table[tid] = task;
	atomic_inc(&os_task_nr);

	task_init(task, name, stack, stk_size, arg,
			prio, tid, aff, opt);

	return task;
}

static void task_create_hook(struct task *task)
{
	do_hooks((void *)task, NULL, OS_HOOK_CREATE_TASK);
}

void task_return_to_user(void)
{
	struct task *task = current;

	if (task->return_to_user)
		task->return_to_user(task);
}

void task_exit_from_user(void)
{
	struct task *task = current;

	if (task->exit_from_user)
		task->exit_from_user(task);
}

void do_release_task(struct task *task)
{
	pr_notice("release task tid: %d name: %s\n",
			task->tid, task->name);

	/*
	 * this function can not be called at interrupt
	 * context, use release_task is more safe
	 */
	release_tid(task->tid);
	atomic_dec(&os_task_nr);

	arch_release_task(task);

	free(task->stack_bottom);
	free(task);
}

void release_task(struct task *task)
{
	unsigned long flags;
	struct pcpu *pcpu = get_pcpu();

	/*
	 * real time task and percpu time all link to
	 * the stop list, and delete from the pcpu global
	 * list, this function will always run ont the current
	 * cpu, mask the idle_block_flag to avoid cpu enter into
	 * idle state
	 */
	spin_lock_irqsave(&pcpu->lock, flags);
	list_add_tail(&pcpu->stop_list, &task->list);
	flag_set(&pcpu->fg, KWORKER_TASK_RECYCLE);
	spin_unlock_irqrestore(&pcpu->lock, flags);
}

void task_exit(int result)
{
	struct task *task = current;

	preempt_disable();

	/*
	 * set the task to stop stat, then call release_task
	 * to release the task
	 */
	task->stat = TASK_STAT_STOPPED;

	/*
	 * to free the resource which the task obtain and releas
	 * it in case to block other task
	 */
	release_task(task);

	preempt_enable();

	/*
	 * nerver return after sched()
	 */
	sched();
	pr_fatal("task exit failed should not be here\n");

	while (1);
}

struct task *__create_task(char *name,
			task_func_t func,
			void *user_sp,
			uint32_t stk_size,
			int prio,
			int aff,
			unsigned long opt,
			void *arg)
{
	struct task *task;
	int tid;

	if ((aff >= NR_CPUS) && (aff != TASK_AFF_ANY)) {
		pr_warn("task %s afinity will set to 0x%x\n",
				name, TASK_AFF_ANY);
		aff = TASK_AFF_ANY;
	}

	if ((prio >= OS_PRIO_IDLE) || (prio < 0)) {
		pr_warn("wrong task prio %d fallback to %d\n",
				prio, OS_PRIO_DEFAULT_6);
		prio = OS_PRIO_DEFAULT_6;
	}

	tid = alloc_tid();
	if (tid < 0)
		return NULL;

	preempt_disable();

	task = do_create_task(name, func, stk_size, prio,
			tid, aff, opt, arg);
	if (!task) {
		release_tid(tid);
		preempt_enable();
		return NULL;
	}

	task_create_hook(task);

	/*
	 * vcpu task will have it own arch_init_task function which
	 * is called arch_init_vcpu()
	 */
	if (!(task->flags & TASK_FLAGS_VCPU))
		arch_init_task(task, (void *)func, user_sp, task->pdata);

	if (task->stat == TASK_STAT_RUNNING)
		task_ready(task, 0);

	preempt_enable();

	if (os_is_running())
		sched();

	return task;
}

struct task *create_task(char *name,
		task_func_t func,
		void *user_sp,
		int prio,
		int aff,
		unsigned long opt,
		void *arg)
{
	if (prio < 0) {
		if (opt & TASK_FLAGS_DRV)
			prio = OS_PRIO_DRIVER;
		else if (opt & OS_PRIO_SYSTEM)
			prio = OS_PRIO_SYSTEM;
		else if (opt & OS_PRIO_VCPU)
			prio = OS_PRIO_VCPU;
		else
			prio = OS_PRIO_DEFAULT;
	}

	return __create_task(name, func, user_sp,
			TASK_STACK_SIZE, prio, aff, opt, arg);
}

int create_idle_task(void)
{
	struct task *task;
	char task_name[32];
	int aff = smp_processor_id();
	int tid = OS_NR_TASKS - 1 - aff;
	struct pcpu *pcpu = get_pcpu();

	task = get_cpu_var(idle_task);
	BUG_ON(!request_tid(tid), "tid is wrong for idle task cpu%d\n", tid);

	os_task_table[tid] = task;
	atomic_inc(&os_task_nr);
	sprintf(task_name, "idle@%d", aff);

	task_init(task, task_name, NULL, 0, NULL, OS_PRIO_IDLE,
			tid, aff, TASK_FLAGS_IDLE | TASK_FLAGS_KERNEL);

	task->stack_top = (void *)ptov(minos_stack_top) - (aff << CONFIG_TASK_STACK_SHIFT);
	task->stack_bottom = task->stack_top - CONFIG_TASK_STACK_SIZE;

	task->stat = TASK_STAT_RUNNING;
	task->run_time = 0;

	pcpu->running_task = task;
	set_current_task(task);

	/* call the hooks for the idle task */
	task_create_hook(task);

	pcpu->local_rdy_grp |= BIT(task->prio);
	pcpu->idle_task = task;

	return 0;
}

void os_for_all_task(void (*hdl)(struct task *task))
{
	int i;
	struct task *task;

	if (hdl == NULL)
		return;

	for (i = 0; i < OS_NR_TASKS; i++) {
		task = os_task_table[i];
		if (!task)
			continue;

		hdl(task);
	}
}

/*
 * for preempt_disable and preempt_enable need
 * to set the current task at boot stage
 */
static int __init_text task_early_init(void)
{
	struct task *task;
	int i = smp_processor_id();

	task = &idle_tasks[i];
	memset(task, 0, sizeof(struct task));
	get_per_cpu(idle_task, i) = task;

	/* init the task info for the thread */
	TASK_INFO_INIT(current_task_info, task);

	return 0;
}
early_initcall_percpu(task_early_init);

int create_percpu_tasks(char *name, task_func_t func, 
		int prio, unsigned long flags, void *pdata)
{
	int cpu;
	struct task *ret;

	if (prio <= OS_PRIO_LOWEST)
		return -EINVAL;

	for_each_online_cpu(cpu) {
		ret = create_task(name, func, NULL, prio, cpu, flags, pdata);
		if (ret == NULL)
			pr_err("create [%s] fail on cpu%d\n", name, cpu);
	}

	return 0;
}
