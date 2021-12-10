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
#include <minos/kobject.h>
#include <minos/uaccess.h>
#include <minos/mm.h>
#include <minos/sched.h>
#include <minos/poll.h>
#include <minos/iqueue.h>

#define EP_RIGHT_MASK	(KOBJ_RIGHT_MMAP | KOBJ_RIGHT_CTL)
#define EP_RIGHT	(KOBJ_RIGHT_RW | KOBJ_RIGHT_CTL)

struct endpoint {
	void *shmem;
	size_t shmem_size;
	struct kobject kobj;			// kobj for this endpoint.
	struct iqueue iqueue;
};

#define kobject_to_endpoint(kobj)	\
	(struct endpoint *)((kobj)->data)

static int endpoint_close(struct kobject *kobj, right_t right, struct process *proc)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);

	iqueue_close(&ep->iqueue, right, proc);

	if (ep->shmem == NULL)
		return 0;
	else
		return unmap_process_memory(proc, va2sva(ep->shmem), ep->shmem_size);
}

static long endpoint_recv(struct kobject *kobj, void __user *data,
		size_t data_size, size_t *actual_data, void __user *extra,
		size_t extra_size, size_t *actual_extra, uint32_t timeout)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);
	return iqueue_recv(&ep->iqueue, data, data_size, actual_data, extra,
			extra_size, actual_extra, timeout);
}

static long endpoint_send(struct kobject *kobj, void __user *data, size_t data_size,
		void __user *extra, size_t extra_size, uint32_t timeout)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);
	return iqueue_send(&ep->iqueue, data, data_size, extra, extra_size, timeout);
}

static int endpoint_reply(struct kobject *kobj, right_t right,
		long token, long errno, handle_t fd, right_t fd_right)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);
	return iqueue_reply(&ep->iqueue, right, token, errno, fd, fd_right);
}

static void endpoint_release(struct kobject *kobj)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);

	if (ep->shmem)
		free_pages(ep->shmem);

	free(ep);
}

static int endpoint_mmap(struct kobject *kobj, right_t right,
		void **addr, unsigned long *msize)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);
	unsigned long base;
	int ret;

	ASSERT(ep->shmem != NULL);
	base = va2sva(ep->shmem);

	ret = map_process_memory(current_proc, base, ep->shmem_size,
			vtop(ep->shmem), VM_RW | VM_SHARED);
	if (ret)
		return ret;

	*addr = (void *)base;
	*msize = ep->shmem_size;

	return 0;
}

static int endpoint_munmap(struct kobject *kobj, right_t right)
{
	struct endpoint *ep = kobject_to_endpoint(kobj);
	unsigned long base;

	ASSERT(ep->shmem != NULL);
	base = va2sva(ep->shmem);

	return unmap_process_memory(current_proc, base, ep->shmem_size);
}

static struct kobject_ops endpoint_kobject_ops = {
	.send		= endpoint_send,
	.recv		= endpoint_recv,
	.release	= endpoint_release,
	.close		= endpoint_close,
	.mmap		= endpoint_mmap,
	.munmap		= endpoint_munmap,
	.reply		= endpoint_reply,
};

static int endpoint_create(struct kobject **kobj, right_t *right, unsigned long data)
{
	size_t shmem_size = data;
	struct endpoint *ep;
	right_t right_ep = EP_RIGHT;

	shmem_size = PAGE_BALIGN(shmem_size);
	if (shmem_size > HUGE_PAGE_SIZE)
		return -E2BIG;

	ep = zalloc(sizeof(struct endpoint));
	if (!ep)
		return -ENOMEM;

	if (shmem_size > 0) {
		ep->shmem = get_free_pages(shmem_size >> PAGE_SHIFT, GFP_USER);
		if (!ep->shmem) {
			free(ep);
			return -ENOMEM;
		}
		right_ep |= KOBJ_RIGHT_MMAP;
	}

	iqueue_init(&ep->iqueue, 0, &ep->kobj);
	kobject_init(&ep->kobj, KOBJ_TYPE_ENDPOINT, EP_RIGHT_MASK, (unsigned long)ep);

	ep->shmem_size = shmem_size;
	ep->kobj.ops = &endpoint_kobject_ops;
	*kobj = &ep->kobj;
	*right = right_ep;

	return 0;
}
DEFINE_KOBJECT(endpoint, KOBJ_TYPE_ENDPOINT, endpoint_create);
