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
#include <minos/mm.h>
#include <minos/sched.h>
#include <uspace/poll.h>
#include <uspace/kobject.h>
#include <uspace/uaccess.h>

struct socket {
	void *shmem;
	size_t shmem_size;

	uint64_t widx;
	uint64_t ridx;

	spinlock_t rlock;
	spinlock_t wlock;

	struct kobject kobj;
};

#define SOCKET_FULL(head, tail) ((head) == (tail) + 1)
#define SOCKET_EMPTY(head, tail) ((head) == (tail))
#define SOCKET_IDX(sk, idx)	\
	((idx) & (sk->shmem_size - 1))

static void socket_release(struct kobject *kobj)
{
	struct socket *sk = (struct socket *)kobj->data;

	free_pages(sk->shmem);
	free(sk);
}

static long endpoint_recv(struct kobject *kobj, void __user *data,
		size_t data_size, size_t *actual_data, void __user *extra,
		size_t extra_size, size_t *actual_extra, uint32_t timeout)
{
	struct socket *sk = (struct socket *)kobj->data;
	uint64_t widx, ridx, head, tail;
	int ret = 0;

	spin_lock(&sk->rlock);

	widx = sk->widx;
	ridx = sk->ridx;
	smp_rmb();

	if (SOCKET_EMPTY(ridx, widx) || (widx - ridx < data_size)) {
		ret = -ENOSPC;
		goto out;
	}

	sk->ridx += data_size;
	smp_wmb();

out:
	spin_unlock(&sk->rlock);
	if (ret)
		return ret;

	/*
	 * copy the data to the target.
	 */
	ridx = SOCKET_IDX(sk, ridx);
	tail = ridx + data_size;
	if (tail > sk->shmem_size) {
		head = shmem_size - ridx;
		tail = tail - shmem_size;
	} else {
		head = data_size;
		tail = 0;
	}

	ret = copy_to_user(data, sk->shmem + ridx, head);
	if (ret <= 0)
		return ret;

	if (tail)
		ret = copy_to_user(data + head, sk->shmem, tail);

	return ret;
}

static long socket_send(struct kobject *kobj, void __user *data,
		size_t data_size, size_t *actual_data, void __user *extra,
		size_t extra_size, size_t *actual_extra, uint32_t timeout)
{
	struct socket *sk = (struct socket *)kobj->data;
	int ret = 0;

	spin_lock(&sk->wlock);

	widx = sk->widx;
	ridx = sk->ridx;
	smp_rmb();

	if (SOCKET_FULL(ridx, widx) || (sk->shmem_size - (widx - ridx) < data_size)) {
		ret = -ENOSPC;
		goto out;
	}

	widx = SOCKET_IDX(sk, widx);
	tail = widx + data_size;
	if (tail > sk->shmem_size) {
		head = shmem_size - widx;
		tail = tail - shmem_size;
	} else {
		head = data_size;
		tail = 0;
	}

	ret = copy_from_user(sk->shmem + widx, data, head);
	if (ret <= 0)
		goto out;

	if (tail) {
		ret = copy_from_user(sk->shmem, data + head, tail);
		if (ret <= 0)
			goto out;
	}

	sk->widx += data_size;
	smp_wmb();

out:
	spin_unlock(&sk->wlock);
	return ret;
}

static struct kobject_ops socket_kobject_ops = {
	.send		= socket_send,
	.recv		= socket_recv,
	.release	= socket_release,
};

static int socket_create(struct kobject **kobj, right_t *right, unsigned long data)
{
	size_t shmem_size = data;
	struct socket *sk;
	int fls;

	if (shmem_size > HUGE_PAGE_SIZE || shmem_size == 0)
		return -EINVAL;

	fls = __fls(shmem_size);
	if (shmem_size & ((1UL << fls) - 1))
		fls += 1;
	shmem_size = (1UL << fls) > PAGE_SIZE ? (1UL << fls) : PAGE_SIZE;

	sk = zalloc(sizeof(struct socket));
	if (!sk)
		return -ENOMEM;

	sk->shmem = get_free_pages(shmem_size >> PAGE_SHIFT, GFP_USER);
	if (!sk->shmem) {
		free(p);
		return -ENOMEM;
	}

	sk->shmem_size = shmem_size;
	spin_lock_init(&sk->rlock);
	spin_lock_init(&sk->wlock);
	sk->kobj.ops = &socket_kobject_ops;
	kobject_init(&sk->kobj, KOBJ_TYPE_SOCKET, 0, (unsigned long)sk);
	*kobj = &sk->kobj;
	*right = KOBJ_RIGHT_RW;

	return 0;
}
