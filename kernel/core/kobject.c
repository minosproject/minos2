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

static void register_kobject_type(kobject_create_cb ops, int type)
{
	BUG_ON(!ops || (type >= KOBJ_TYPE_MAX));

	if (kobj_create_cbs[type] != NULL)
		pr_warn("overwrite kobject ops for %d\n", type);
	kobj_create_cbs[type] = ops;
}

static void kobject_release(struct kobject *kobj)
{
	/*
	 * release poll_struct if needed.
	 */
	release_poll_struct(kobj);

	if (kobj->ops && kobj->ops->release)
		kobj->ops->release(kobj);
}

int kobject_get(struct kobject *kobj)
{
	int old;

	if (!kobj)
		return 0;

	old = atomic_inc_if_postive(&kobj->ref);
	if (old < 0) {
		pr_err("%s: wrong refcount %d 0x%p\n", __func__, old, kobj);
		return 0;
	}

	return 1;
}

int kobject_put(struct kobject *kobj)
{
	int old;

	if (!kobj)
		return 0;

	old = atomic_dec_set_negtive_if_zero(&kobj->ref);
	if (old <= 0) {
		pr_err("%s: wrong refcount %d 0x%p\n", __func__, old, kobj);
		return 0;
	}

	/*
	 * if the old value is 1, then release the kobject.
	 */
	if (old == 1)
		kobject_release(kobj);

	return 1;
}

void kobject_init(struct kobject *kobj, int type,
		right_t right_mask, unsigned long data)
{

	BUG_ON((!kobj));
	kobj->right_mask = right_mask;
	kobj->type = type;
	kobj->data = data;
	kobj->list.pre = NULL;
	kobj->list.next = NULL;
}

int kobject_create(int type, struct kobject **kobj, right_t *right, unsigned long data)
{
	kobject_create_cb ops;

	if ((type <= 0) || (type >= KOBJ_TYPE_MAX))
		return -ENOENT;

	ops = kobj_create_cbs[type];
	if (!ops)
		return -EOPNOTSUPP;

	return ops(kobj, right, data);
}

int kobject_poll(struct kobject *ksrc, struct kobject *kdst, int event, bool enable)
{
	if (ksrc->ops && ksrc->ops->poll)
		return ksrc->ops->poll(ksrc, kdst, event, enable);
	else
		return 0;
}

int kobject_open(struct kobject *kobj, handle_t handle, right_t right)
{
	int ret;

	if (!kobj->ops || !kobj->ops->open)
		return 0;

	ret = kobj->ops->open(kobj, handle, right);
	if (ret)
		return ret;

	if (right & KOBJ_RIGHT_WRITE)
		poll_event_send(kobj->poll_struct, EV_WOPEN);
	else
		poll_event_send(kobj->poll_struct, EV_ROPEN);

	return 0;
}

int kobject_close(struct kobject *kobj, right_t right)
{
	int ret = 0;

	/*
	 * just put this kobject if the right is 0.
	 */
	if (right == KOBJ_RIGHT_NONE) {
		kobject_put(kobj);
		return 0;
	}

	if (!kobj->ops || !kobj->ops->close)
		return 0;

	ret = kobj->ops->close(kobj, right);

	/*
	 * send the close event to the poller if need.
	 */
	if (right & KOBJ_RIGHT_WRITE) {
		poll_event_send(kobj->poll_struct, EV_WCLOSE);
		if (kobj->poll_struct)
			kobj->poll_struct->poll_events &= ~(POLLIN | POLLWOPEN | POLLWCLOSE);
	} else if (right & KOBJ_RIGHT_READ) {
		poll_event_send(kobj->poll_struct, EV_RCLOSE);
		if (kobj->poll_struct)
			kobj->poll_struct->poll_events &= ~(POLLOUT |
					POLLROPEN | POLLRCLOSE | POLLKERNEL);
	}

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

	/*
	 * before read, if there is task waitting the event
	 * to be read, here can send EV_OUT event to notify
	 * the target task to send new data.
	 */
	poll_event_send(kobj->poll_struct, EV_OUT);

	return kobj->ops->recv(kobj, data, data_size, actual_data,
			extra, extra_size, actual_extra, timeout);
}

long kobject_send(struct kobject *kobj, void __user *data, size_t data_size,
		void __user *extra, size_t extra_size, uint32_t timeout)
{
	if (!kobj->ops || !kobj->ops->send)
		return -EACCES;
	/*
	 * the poll event must called by the kobject itself
	 */
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
