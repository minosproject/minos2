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
#include <minos/task.h>
#include <minos/poll.h>

static kobject_create_cb kobj_create_cbs[KOBJ_TYPE_MAX];

void register_kobject_type(kobject_create_cb ops, int type)
{
	BUG_ON(!ops || (type >= KOBJ_TYPE_MAX));

	if (kobj_create_cbs[type] != NULL)
		pr_warn("overwrite kobject ops for %d\n", type);
	kobj_create_cbs[type] = ops;
}

static void kobject_release(struct kobject *kobj)
{
	if (kobj->ops && kobj->ops->release)
		kobj->ops->release(kobj);
}

/*
 * get -> put case
 * kobject_create  -> kobject_close
 * kobject_connect -> kobject_close
 * get_kobject     -> put_kobject
 */
int kobject_get(struct kobject *kobj)
{
	int old;

	if (!kobj)
		return 0;

	old = atomic_cmpadd(&kobj->ref, 0, 1);
	if (old == 0) {
		pr_err("wrong refcount %d for 0x%p\n", old, kobj);
		return 0;
	}

	return old;
}

int kobject_put(struct kobject *kobj)
{
	int old;

	if (!kobj)
		return 0;

	old = atomic_cmpsub(&kobj->ref, 0, 1);
	if (old == 0) {
		pr_err("wrong refcount %d for 0x%p\n", old, kobj);
		return 0;
	}

	/*
	 * if the old value is 1, then release the kobject.
	 */
	if (old == 1)
		kobject_release(kobj);

	return old;
}

void kobject_init(struct kobject *kobj, int type, right_t right, unsigned long data)
{

	BUG_ON((!kobj));
	kobj->right = right;
	kobj->type = type;
	kobj->data = data;
	kobj->list.pre = NULL;
	kobj->list.next = NULL;
	spin_lock_init(&kobj->poll_struct.lock);
}

struct kobject *kobject_create(int type, right_t right,
		right_t right_req, unsigned long data)
{
	kobject_create_cb ops;
	struct kobject *kobj;

	if ((type <= 0) || (type >= KOBJ_TYPE_MAX))
		return ERROR_PTR(-ENOENT);

	ops = kobj_create_cbs[type];
	if (!ops)
		return ERROR_PTR(-EACCES);

	kobj = ops(right, right_req, data);
	if (IS_ERROR_PTR(kobj))
		return kobj;

	kobj->type = type;
	return kobj;
}

int kobject_poll(struct kobject *ksrc, struct kobject *kdst, int event, bool enable)
{
	int ret = 0;

	if (ksrc->ops && ksrc->ops->poll)
		ret = ksrc->ops->poll(ksrc, kdst, event, enable);

	if (enable) {
		if (ret == 0)
			kobject_get(kdst);
	} else {
		kobject_put(kdst);
	}

	return 0;
}

int kobject_open(struct kobject *kobj, handle_t handle, right_t right)
{
	if (!kobj->ops || !kobj->ops->open)
		return 0;

	return kobj->ops->open(kobj, handle, right);
}

int kobject_close(struct kobject *kobj, right_t right)
{
	struct poll_struct *ps = &kobj->poll_struct;
	int ret = 0;
	int events;

	if (!kobj->ops || !kobj->ops->close)
		ret = kobj->ops->close(kobj, right);

	/*
	 * if the kobject has been polled, release the poll
	 * event in poll_hub.
	 */
	events = ps->poll_event;
	ps->poll_event = 0;
	smp_wmb();

	if ((events & POLLIN) && ((right & KOBJ_RIGHT_RW) == KOBJ_RIGHT_WRITE))
		poll_event_send_with_data(ps, POLLIN, POLLIN_KOBJ_CLOSE, 0, 0, 0);

	if ((events & POLLOUT) && ((right & KOBJ_RIGHT_RW) == KOBJ_RIGHT_READ))
		poll_event_send_with_data(ps, POLLOUT, POLLIN_KOBJ_CLOSE, 0, 0, 0);

	if (events & POLLIN)
		kobject_poll(kobj, ps->infos[0].poller, POLLIN, false);
	if (events & POLLOUT)
		kobject_poll(kobj, ps->infos[1].poller, POLLOUT, false);

	memset(ps, 0, sizeof(struct poll_struct));

	/*
	 * dec the refcount which caused by kobject_init and
	 * kobject_connect.
	 */
	kobject_put(kobj);

	return ret;
}

long kobject_recv(struct kobject *kobj, void __user *data, size_t data_size,
		size_t *actual_data, void __user *extra, size_t extra_size,
		size_t *actual_extra, uint32_t timeout)
{
	if (!kobj->ops || !kobj->ops->recv)
		return -EACCES;

	return kobj->ops->recv(kobj, data, data_size, actual_data,
			extra, extra_size, actual_extra, timeout);
}

long kobject_send(struct kobject *kobj, void __user *data, size_t data_size,
		void __user *extra, size_t extra_size, uint32_t timeout)
{
	if (!kobj->ops || !kobj->ops->send)
		return -EACCES;

	return kobj->ops->send(kobj, data, data_size, extra,
			extra_size, timeout);
}

int kobject_reply(struct kobject *kobj, right_t right, unsigned long token,
		long err_code, handle_t fd, right_t fd_right)
{
	if (!kobj->ops || !kobj->ops->reply)
		return -EPERM;

	return kobj->ops->reply(kobj, right, token, err_code, fd, fd_right);
}

int kobject_munmap(struct kobject *kobj, right_t right)
{
	if (!kobj->ops || !kobj->ops->munmap)
		return -EPERM;

	return kobj->ops->munmap(kobj, right);
}

void *kobject_mmap(struct kobject *kobj, right_t right)
{
	if (!kobj->ops || !kobj->ops->mmap)
		return (void *)-1;

	return kobj->ops->mmap(kobj, right);
}

long kobject_ctl(struct kobject *kobj, right_t right,
		int req, unsigned long data)
{
	if (!kobj->ops || !kobj->ops->ctl)
		return -EPERM;

	return kobj->ops->ctl(kobj, req, data);
}

handle_t kobject_send_handle(struct process *psrc, struct process *pdst,
		handle_t handle, right_t right_send)
{
	struct kobject *kobj;
	right_t right;
	int ret;

	ret = get_kobject_from_process(psrc, handle, &kobj, &right);
	if (ret)
		return ret;

	if (!(right & KOBJ_RIGHT_GRANT)) {
		ret = -EPERM;
		goto out;
	}

	if ((right_send & KOBJ_RIGHT_RW) == (right & KOBJ_RIGHT_RW)) {
		ret = -EPERM;
		goto out;
	}

	right_send &= KOBJ_RIGHT_RW;
	ret =  __alloc_handle(pdst, kobj, right_send);
out:
	put_kobject(kobj);
	return ret;
}

handle_t sys_grant(handle_t proc_handle, handle_t handle, right_t right)
{
	struct kobject *kobj_proc, *kobj;
	right_t right_proc, right_kobj;
	handle_t handle_out = -1;
	struct process *proc;
	int ret;

	/*
	 * only the root service can call this function, other
	 * process if need pass an kobject to another thread, may
	 * have its owm proto
	 */
	if (current_proc->kobj.right != KOBJ_RIGHT_ROOT)
		return -EPERM;

	if (WRONG_HANDLE(proc_handle) || WRONG_HANDLE(handle))
		return -ENOENT;

	ret = get_kobject(proc_handle, &kobj_proc, &right_proc);
	if (ret)
		return -ENOENT;

	ret = get_kobject(handle, &kobj, &right_kobj);
	if (ret) {
		put_kobject(kobj_proc);
		return -ENOENT;
	}

	if ((kobj_proc->type != KOBJ_TYPE_PROCESS) ||
			!(kobj->right & KOBJ_RIGHT_GRANT)) {
		handle_out = -EBADF;
		goto out;
	}

	if ((kobj->right & right) != right) {
		handle_out = -EPERM;
		goto out;
	}

	proc = (struct process *)kobj_proc->data;
	handle_out = __alloc_handle(proc, kobj, right);

out:
	put_kobject(kobj_proc);
	put_kobject(kobj);

	return handle_out;
}

static int kobject_subsystem_init(void)
{
	extern unsigned long __kobject_desc_start;
	extern unsigned long __kobject_desc_end;
	struct kobject_desc *desc;

	section_for_each_item(__kobject_desc_start, __kobject_desc_end, desc) {
		if (desc->type >= KOBJ_TYPE_MAX) {
			pr_err("Unsupported kobject type [%d] name [%s]\n",
					desc->type, desc->name);
			continue;
		}

		pr_notice("Register kobject type [%d] name [%s]\n",
				desc->type, desc->name);
		register_kobject_type(desc->ops, desc->type);
	}

	return 0;
}
subsys_initcall(kobject_subsystem_init);
