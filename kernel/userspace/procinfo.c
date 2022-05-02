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
#include <minos/time.h>
#include <minos/atomic.h>
#include <minos/task.h>
#include <uspace/kobject.h>
#include <uspace/proc.h>
#include <uapi/procinfo_uapi.h>

struct kobject *task_stat_pma;
static struct task_stat *task_stat_addr;

struct task_stat *get_task_stat(int tid)
{
	ASSERT((tid >= 0) && (tid < OS_NR_TASKS));
	return &task_stat_addr[tid]; 
}

void release_task_stat(int tid)
{
	ASSERT((tid >= 0) && (tid < OS_NR_TASKS));
	memset(&task_stat_addr[tid], 0, sizeof(struct task_stat));
}

void init_task_stat(struct task *task)
{
	struct task_stat *kstat;
	struct process *proc;

	if (task_stat_addr == NULL)
		return;

	kstat = get_task_stat(task->tid);
	kstat->tid = task->tid;
	kstat->pid = task->pid;
	kstat->start_ns = task->start_ns;
	kstat->state = task->state;
	kstat->cpu = task->cpu;
	kstat->prio = task->prio;
	kstat->cpu_usage = 0x0;

	if (!(task->flags & TASK_FLAGS_KERNEL)) {
		proc = task_to_proc(task);
		if (proc->root_task)
			kstat->root_tid = proc->root_task->tid;
	}
}

void update_task_stat(struct task *task)
{
	struct task_stat *kstat = get_task_stat(task->tid);

	kstat->state = task->state;
	kstat->cpu = task->cpu;
	kstat->cpu_usage = 0x0;
	kstat->prio = task->prio;
}

static int procinfo_switch_hook(void *item, void *data)
{
	update_task_stat((struct task *)item);
	update_task_stat((struct task *)data);

	return 0;
}

static void init_kernel_task_stat(struct task *task)
{
	struct task_stat *ts;

	if (!(task->flags & TASK_FLAGS_KERNEL))
		return;

	ts = get_task_stat(task->tid);
	strcpy(ts->cmd, task->name);
	init_task_stat(task);
}

int procinfo_init(void)
{
	struct pma_create_arg args;
	uint32_t memsz;
	right_t right;
	int ret;

	/*
	 * allocate pma kobject for process and task info which
	 * can shared to each process in these system.
	 */
	memsz = sizeof(struct task_stat) * OS_NR_TASKS;
	memsz = PAGE_BALIGN(memsz);
	task_stat_addr = get_free_pages(memsz >> PAGE_SHIFT, GFP_USER);
	ASSERT(task_stat_addr != NULL);
	args.type = PMA_TYPE_PMEM;
	args.right = KOBJ_RIGHT_RW;
	args.consequent = 1;
	args.start = vtop(task_stat_addr);
	args.size = memsz;
	ret = create_new_pma(&task_stat_pma, &right, &args);
	ASSERT(ret == 0);
	memset(task_stat_addr, 0, memsz);
	pr_info("task stat memory size 0x%x\n", memsz);

	register_hook(procinfo_switch_hook, OS_HOOK_TASK_SWITCH);

	/*
	 * init the kernel task's task stat.
	 */
	os_for_all_task(init_kernel_task_stat);

	return 0;
}
