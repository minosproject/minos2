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
#include <minos/kobject.h>

struct kobject *uproc_info_pma;
struct kobject *ktask_stat_pma;

static struct uproc_info *uproc_info_addr;
static struct ktask_stat *ktask_stat_addr;

static int procinfo_init(void)
{
	struct pma_create_arg args;
	uint32_t memsz;
	right_t right;
	int ret;

	/*
	 * allocate pma kobject for process and task info which
	 * can shared to each process in these system.
	 */
	memsz = sizeof(struct ktask_stat) * OS_NR_TASKS;
	memsz = PAGE_BALIGN(memsz);
	ktask_stat_addr = get_free_pages(memsz >> PAGE_SHIFT, GFP_USER);
	ASSERT(ktask_stat_addr != NULL);
	args.type = PMA_TYPE_PMEM;
	args.right = KOBJ_RIGHT_RW;
	args.consequent = 1;
	args.start = vtop(ktask_stat_addr);
	args.size = memsz;
	ret = create_new_pma(&ktask_stat_pma, &right, &args);
	ASSERT(ret == 0);
	memset(ktask_stat_addr, 0, memsz);
	pr_info("ktask stat memory size 0x%x\n", memsz);

	memsz = sizeof(struct uproc_info) * OS_NR_TASKS;
	memsz = PAGE_BALIGN(memsz);
	uproc_info_addr = get_free_pages(memsz >> PAGE_SHIFT, GFP_USER);
	ASSERT(uproc_info_addr != NULL);
	args.type = PMA_TYPE_PMEM;
	args.right = KOBJ_RIGHT_RW;
	args.consequent = 1;
	args.start = vtop(uproc_info_addr);
	args.size = memsz;
	ret = create_new_pma(&uproc_info_pma, &right, &args);
	ASSERT(ret == 0);
	memset(uproc_info_addr, 0, memsz);
	pr_info("uproc info memory size 0x%x\n", memsz);

	return 0;
}
module_initcall(procinfo_init);

struct uproc_info *get_uproc_info(int pid)
{
	ASSERT((pid >= 0) && (pid < OS_NR_TASKS));
	return &uproc_info_addr[pid];
}

struct ktask_stat *get_ktask_stat(int tid)
{
	ASSERT((tid >= 0) && (tid < OS_NR_TASKS));
	return &ktask_stat_addr[tid]; 
}

void release_ktask_stat(int tid)
{
	ASSERT((tid >= 0) && (tid < OS_NR_TASKS));
	memset(&ktask_stat_addr[tid], 0, sizeof(struct ktask_stat));
}

void init_ktask_stat(struct task *task)
{
	struct ktask_stat *kstat = task->kstat;

	kstat->valid = 1;
	kstat->pid = task->pid;
	kstat->tid = task->tid;
	kstat->start_ns = NOW();

	kstat->state = task->stat;
	kstat->cpu = task->cpu;
	kstat->prio = task->prio;
	kstat->cpu_usage = 0x0;
}

void get_and_init_ktask_stat(struct task *task)
{
	task->kstat = get_ktask_stat(task->tid);
	init_ktask_stat(task);
}

void update_ktask_stat(struct task *task)
{
	struct ktask_stat *kstat = task->kstat;

	kstat->state = task->stat;
	kstat->cpu = task->cpu;
	kstat->cpu_usage = 0x0;
	kstat->prio = task->prio;
}
