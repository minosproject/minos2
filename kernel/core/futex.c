/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
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
#include <minos/vspace.h>
#include <minos/mm.h>
#include <minos/time.h>
#include <minos/task.h>
#include <minos/sched.h>

#define FUTEX_WAIT              0
#define FUTEX_WAKE              1
#define FUTEX_FD                2
#define FUTEX_REQUEUE           3
#define FUTEX_CMP_REQUEUE       4
#define FUTEX_WAKE_OP           5
#define FUTEX_LOCK_PI           6
#define FUTEX_UNLOCK_PI         7
#define FUTEX_TRYLOCK_PI        8
#define FUTEX_WAIT_BITSET       9
#define FUTEX_WAKE_BITSET       10
#define FUTEX_WAIT_REQUEUE_PI   11
#define FUTEX_CMP_REQUEUE_PI    12
#define FUTEX_SWAP              13

#define FUTEX_PRIVATE_FLAG      128
#define FUTEX_CLOCK_REALTIME    256
#define FUTEX_CMD_MASK          ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)

#define FUTEX_WAIT_PRIVATE      (FUTEX_WAIT | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_PRIVATE      (FUTEX_WAKE | FUTEX_PRIVATE_FLAG)
#define FUTEX_REQUEUE_PRIVATE   (FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG)
#define FUTEX_CMP_REQUEUE_PRIVATE (FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_OP_PRIVATE   (FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG)
#define FUTEX_LOCK_PI_PRIVATE   (FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG)
#define FUTEX_UNLOCK_PI_PRIVATE (FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG)
#define FUTEX_TRYLOCK_PI_PRIVATE (FUTEX_TRYLOCK_PI | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAIT_BITSET_PRIVATE       (FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_BITSET_PRIVATE       (FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAIT_REQUEUE_PI_PRIVATE   (FUTEX_WAIT_REQUEUE_PI | \
                                         FUTEX_PRIVATE_FLAG)
#define FUTEX_CMP_REQUEUE_PI_PRIVATE    (FUTEX_CMP_REQUEUE_PI | \
                                         FUTEX_PRIVATE_FLAG)
#define FUTEX_SWAP_PRIVATE              (FUTEX_SWAP | FUTEX_PRIVATE_FLAG)

struct futex {
	pid_t owner;
	unsigned long paddr;
	spinlock_t lock;
	struct list_head wait_list;
	struct list_head list;
};

struct futex_queue {
	int cnt;
	spinlock_t lock;
	struct list_head head;
};

#define FUTEX_KEY_SIZE	10
static struct futex_queue ft_queue[FUTEX_KEY_SIZE];

static unsigned long futex_timeout_val(struct timespec *ktime)
{
	// TBD overfolw check
	return (ktime->tv_sec * 1000ULL) + (ktime->tv_nsec / 1000000ULL);
}

static long sys_do_futex_wait(struct futex *ft, uint32_t *kaddr,
		uint32_t val, struct timespec *ktime,
		uint32_t *kaddr2, uint32_t val3)
{
	long ret = 0;
	unsigned long timeout;

	timeout = ktime ? futex_timeout_val(ktime) : 0;

	/*
	 * the lock may has been released, return to userspace
	 * again to require the lock at userspace. else wait on
	 * this futex's wiat list.
	 */
	spin_lock(&ft->lock);
	if (*kaddr != val) {
		spin_unlock(&ft->lock);
		return 0;
	}
	list_add_tail(&ft->wait_list, &current->list);
	__wait_event(ft, OS_EVENT_TYPE_FUTEX, timeout);
	spin_unlock(&ft->lock);

	ret = do_wait();

	ASSERT(current->list.next != NULL);
	spin_lock(&ft->lock);
	list_del(&current->list);
	spin_unlock(&ft->lock);

	return ret;
}

static long sys_do_futex_wake(struct futex *ft, uint32_t *kaddr,
		uint32_t val, struct timespec *ktime,
		uint32_t *kaddr2, uint32_t val3)
{
	int wakecnt = 0;
	struct task *task, *tmp;

	if ((val != 1) && (val != INT_MAX)) {
		pr_warn("bad value for futex wake %d\n", val);
		return -EINVAL;
	}

	spin_lock(&ft->lock);
	list_for_each_entry_safe(task, tmp, &ft->wait_list, list) {
		wake_up(task, 0);
		wakecnt++;
		if (wakecnt == val)
			break;
	}
	spin_unlock(&ft->lock);

	return wakecnt;
}

static inline int futex_key(unsigned long phy)
{
	return (phy >> PAGE_SHIFT) % 10;
}

static inline int is_wait_cmd(int cmd)
{
	if (cmd == FUTEX_WAIT || cmd == FUTEX_LOCK_PI ||
                      cmd == FUTEX_WAIT_BITSET ||
                      cmd == FUTEX_WAIT_REQUEUE_PI)
		return 1;
	else
		return 0;
}

long sys_futex(uint32_t __user *uaddr, int op, uint32_t val,
		struct timespec __user *utime,
		uint32_t __user *uaddr2, uint32_t val3)
{
	struct vspace *vs = &current_proc->vspace;
	struct timespec *ktime = NULL;
	struct futex_queue *ftq;
	struct futex *ft = NULL, *tmp;
	uint32_t *kaddr, *kaddr2 = NULL;
	unsigned long paddr;
	unsigned int key;
	int cmd = op & FUTEX_CMD_MASK;

	kaddr = uva_to_kva(vs, ULONG(uaddr), sizeof(uint32_t), VM_RW);
	if (kaddr == NULL)
		return -EFAULT;

	if (utime && (cmd == FUTEX_WAIT || cmd == FUTEX_LOCK_PI ||
                      cmd == FUTEX_WAIT_BITSET ||
                      cmd == FUTEX_WAIT_REQUEUE_PI)) {
		ktime = uva_to_kva(vs, ULONG(utime), sizeof(struct timespec), VM_RW);
		if (ktime == NULL)
			return -EFAULT;
	}

	if (uaddr2) {
		kaddr2 = uva_to_kva(vs, ULONG(uaddr2), sizeof(uint32_t), VM_RW);
		if (kaddr2 == NULL)
			return -EFAULT;
	}

	paddr = vtop(kaddr);
	key = futex_key(paddr);
	ASSERT(key < FUTEX_KEY_SIZE);
	ftq = &ft_queue[key];

	spin_lock(&ftq->lock);
	list_for_each_entry(tmp, &ftq->head, list) {
		if (tmp->paddr == paddr) {
			ft = tmp;
			break;
		}
	}

	if (!ft && !is_wait_cmd(cmd)) {
		spin_unlock(&ftq->lock);
		return -ENOENT;
	}

	if (!ft) {
		ft = zalloc(sizeof(struct futex));
		if (!ft) {
			spin_unlock(&ftq->lock);
			return -ENOMEM;
		}

		ft->owner = current_pid;
		ft->paddr = paddr;
		spin_lock_init(&ft->lock);
		init_list(&ft->wait_list);
		list_add(&ftq->head, &ft->list);
	}
	spin_unlock(&ftq->lock);

	switch (cmd) {
	case FUTEX_WAIT:
		return sys_do_futex_wait(ft, kaddr, val, ktime, kaddr2, val3);
	case FUTEX_WAKE:
		return sys_do_futex_wake(ft, kaddr, val, ktime, kaddr2, val3);
	default:
		break;
	}

	return -ENOSYS;
}

static int futex_subsys_init(void)
{
	int i;

	for (i = 0; i < FUTEX_KEY_SIZE; i++) {
		init_list(&ft_queue[i].head);
		spin_lock_init(&ft_queue[i].lock);
	}

	return 0;
}
subsys_initcall(futex_subsys_init);
