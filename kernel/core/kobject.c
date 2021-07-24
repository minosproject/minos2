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

void kobject_add(struct kobject *kobj)
{
	struct process *proc = current_proc;
	unsigned long flags;

	/*
	 * add kobject will export a interface to other
	 * process, then other process can connect the kobject
	 * to communicated with this process.
	 */
	spin_lock_irqsave(&proc->lock, flags);
	list_add_tail(&proc->kobj.child, &kobj->parent);
	spin_unlock_irqrestore(&proc->lock, flags);
}

void kobject_delete(struct kobject *kobj)
{
	struct process *proc = current_proc;
	unsigned long flags;

	if (kobj->type == KOBJ_TYPE_PROCESS)
		return;

	if (kobj->owner != current_pid)
		return;

	/*
	 * add port will export a port to other
	 * process, then other process can open the port
	 * to communicated with this process.
	 *
	 * the port object will add to the process's
	 * namespace kobject's list.
	 */
	spin_lock_irqsave(&proc->lock, flags);
	list_del(&kobj->parent);
	spin_unlock_irqrestore(&proc->lock, flags);
}

struct kobject *get_kobject_by_name(struct kobject *root, const char *name)
{
	struct process *proc = (struct process *)root->data;
	unsigned long flags;
	struct kobject *kobj, *ret = NULL;

	if ((root->type != KOBJ_TYPE_PROCESS) || !proc)
		return NULL;

	spin_lock_irqsave(&proc->lock, flags);
	list_for_each_entry(kobj, &root->child, parent) {
		if (!kobj->name || (kobj->flags & KOBJ_FLAGS_INVISABLE))
			continue;

		if (strcmp(kobj->name, name) == 0) {
			if (kobject_get(kobj))
				ret = kobj;
			break;
		}
	}
	spin_unlock_irqrestore(&proc->lock, flags);

	return ret;
}

void kobject_init(struct kobject *kobj, pid_t owner, int type,
		int flags, right_t right, unsigned long data)
{

	BUG_ON((!kobj));
	kobj->right = right;
	kobj->type = type;
	kobj->flags = flags;
	kobj->owner = owner;
	kobj->data = data;
	kobj->list.pre = NULL;
	kobj->list.next = NULL;
	init_list(&kobj->child);
	spin_lock_init(&kobj->poll_struct.lock);

	/*
	 * the initial value of ref is 1, so kobject_create do not
	 * need to call kobject_get();
	 */
	atomic_set(1, &kobj->ref);
}

struct kobject *kobject_create(char *name, int type, right_t right,
		right_t right_req, unsigned long data)
{
	kobject_create_cb ops;
	struct kobject *kobj;

	if ((type <= 0) || (type >= KOBJ_TYPE_MAX))
		return ERROR_PTR(-ENOENT);

	ops = kobj_create_cbs[type];
	if (!ops)
		return ERROR_PTR(-EACCES);

	kobj = ops(name, right, right_req, data);
	if (IS_ERROR_PTR(kobj))
		return kobj;

	kobj->type = type;
	return kobj;
}

int kobject_poll(struct kobject *ksrc, int event, int enable)
{
	if (!ksrc->ops || !ksrc->ops->poll)
		return 0;

	return ksrc->ops->poll(ksrc, event, enable);
}

int kobject_open(struct kobject *kobj, handle_t handle, right_t right)
{
	if (!kobj->ops || !kobj->ops->open)
		return 0;

	return kobj->ops->open(kobj, handle, right);
}

int kobject_connect(char *name, right_t right)
{
	struct kobject *kobj;
	char *realname;
	int ret;
	handle_t handle;

	ret = get_kobject_from_namespace(name, &kobj, &realname);
	if (ret)
		return -ENOENT;

	if (kobj->right & KOBJ_FLAGS_INVISABLE) {
		ret = -EACCES;
		goto out;
	}

	/*
	 * the owner of this kobject can not connect it.
	 */
	if ((current_pid == kobj->owner) ||
			!kobj->ops || !kobj->ops->connect) {
		ret = -EPERM;
		goto out;
	}

	/*
	 * TBD some IPC methold may support pass argument to the
	 * userspace.
	 */
	if (realname != NULL) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * if the kobject do not have the request right, return
	 * error.
	 */
	if ((right & kobj->right) != right) {
		ret = -EPERM;
		goto out;
	}

	/*
	 * everything is ok, allocate a new handle for the process
	 * and return to the application, the open the kobject.
	 *
	 * first allocate a handle with temp invalid kobject, if
	 * connect is successfully, the truly kobject and right will
	 * fill to the handle.
	 */
	handle = alloc_handle((struct kobject *)-1, 0);
	if (ret <= 0) {
		ret = -ENOSPC;
		goto out;
	}

	ret = kobj->ops->connect(kobj, handle, right);
	if (ret) {
		release_handle(handle);
		ret = -EIO;
	}

	setup_handle(handle, kobj, right);
out:
	if (ret)
		kobject_put(kobj);

	return ret;
}

int kobject_close(struct kobject *kobj, right_t right)
{
	int ret = 0;

	if (current_pid == kobj->owner)
		return -EPERM;

	if (!kobj->ops || !kobj->ops->close)
		ret = kobj->ops->close(kobj, right);

	/*
	 * kobject_close will delete the kobject from the process's
	 * forcely no matter whether there some process is connected
	 * it, after it detached from the process, no process can
	 * open or connected it, then it can wait all the process
	 * which opened it to close it and release it resource.
	 *
	 * the kobject_put here is corresponds to kobject_create
	 *
	 * close will not truly release all the resource of this kobject
	 * when the reference is 0, then kobject_put will the release
	 * callback to release the resource of this kobject.
	 *
	 * first need to check whether this kobject is connected to
	 * the process, the kernel irq will not belong to any process.
	 */
	if ((current_pid == kobj->owner) && (kobj->parent.next != NULL))
		kobject_delete(kobj);
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

	return kobj->ops->send(kobj, data, data_size, extra, extra_size, timeout);
}

int kobject_reply(struct kobject *kobj, right_t right,
			unsigned long token, long err_code)
{
	if (!kobj->ops || !kobj->ops->reply)
		return -EPERM;

	return kobj->ops->reply(kobj, right, token, err_code);
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

handle_t sys_grant(handle_t proc_handle, handle_t handle,
		right_t right, int release)
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

	/*
	 * change the owner.
	 */
	proc = (struct process *)kobj_proc->data;
	kobj->owner = proc->pid;
	handle_out = __alloc_handle(proc, kobj, right);

	if (release) {
		// TBD
	}

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
