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
#include <minos/handle.h>
#include <minos/mm.h>

#define to_handle_table_desc(hdesc)	\
	(struct handle_table_desc *)&hdesc[NR_DESC_PER_PAGE]

static struct handle_desc *new_handle_desc_table(uint32_t index)
{
	struct handle_desc *dt;
	struct handle_table_desc *htd;

	if (index >= PROC_MAX_HANDLE) {
		pr_err("handle table too big exceed %d\n", PROC_MAX_HANDLE);
		return NULL;
	}

	dt = get_free_page(GFP_KERNEL);
	if (!dt)
		return NULL;
	memset(dt, 0, PAGE_SIZE);

	htd = to_handle_table_desc(dt);
	htd->left = NR_DESC_PER_PAGE;
	htd->index = index;
	htd->next = NULL;

	return dt;
}

static int __alloc_new_handle(struct handle_table_desc *htd,
		handle_t *handle, struct handle_desc **hd)
{
	struct handle_desc *table;
	struct handle_table_desc *new_htd;

	table = new_handle_desc_table(htd->index + NR_DESC_PER_PAGE);
	if (!table)
		return -ENOMEM;

	htd->next = table;
	new_htd = to_handle_table_desc(table);
	new_htd->left -= 1;

	*handle = new_htd->index;
	*hd = &table[0];

	return 0;
}

static int lookup_handle_desc(struct process *proc, handle_t handle,
		struct handle_desc **hd,
		struct handle_table_desc **htd)
{
	struct handle_desc *table = proc->handle_desc_table;
	struct handle_table_desc *tdesc = to_handle_table_desc(table);

	while (handle >= NR_DESC_PER_PAGE) {
		handle -= NR_DESC_PER_PAGE;
		table = tdesc->next;
		tdesc = to_handle_table_desc(table);
	}

	*hd = &table[handle];
	*htd = tdesc;

	return 0;
}

int release_handle(handle_t handle, struct kobject **kobj, right_t *right)
{
	struct process *proc = current_proc;
	struct handle_desc *hd;
	struct handle_table_desc *htd;
	int ret = -ENOENT;

	if (WRONG_HANDLE(handle) || !proc)
		return -ENOENT;

	spin_lock(&proc->kobj_lock);
	ret = lookup_handle_desc(proc, handle, &hd, &htd);
	if (ret)
		goto out;

	if (hd->kobj == NULL || hd->kobj == KOBJ_PLACEHOLDER) {
		ret = -EPERM;
		goto out;
	}

	*kobj = hd->kobj;
	*right = hd->right;

	hd->kobj = NULL;
	hd->right = KOBJ_RIGHT_NONE;
	htd->left++;
out:
	spin_unlock(&proc->kobj_lock);

	return ret;
}

static inline int __alloc_handle_internal(struct handle_desc *desc,
		struct handle_table_desc *htd, handle_t *handle,
		struct handle_desc **hd)
{
	int i;

	if (htd->left == 0)
		return -ENOSPC;

	for (i = 0; i < NR_DESC_PER_PAGE; i++) {
		if (desc[i].kobj == NULL) {
			*handle = i + htd->index;
			*hd = &desc[i];
			return 0;
		}
	}

	ASSERT(0);
	return -ENOSPC;
}

handle_t __alloc_handle(struct process *proc, struct kobject *kobj, right_t right)
{
	struct handle_desc *hd = proc->handle_desc_table;
	struct handle_table_desc *htd = to_handle_table_desc(hd);
	handle_t handle = HANDLE_NULL;
	struct handle_desc *hdesc;
	int ret = -ENOSPC;

	ASSERT(kobj != NULL);
	ASSERT(proc != NULL);

	spin_lock(&proc->kobj_lock);

	do {
		ret = __alloc_handle_internal(hd, htd, &handle, &hdesc);
		if (ret == 0)
			break;
		hd = htd->next;
	} while (hd != NULL);

	if (ret != 0) {
		ret = __alloc_new_handle(htd, &handle, &hdesc);
		if (ret) {
			handle = HANDLE_NULL;
			goto out;
		}
	}

	hdesc->kobj = kobj;
	hdesc->right = right;
	kobject_get(kobj);
out:
	spin_unlock(&proc->kobj_lock);
	
	return handle;
}

handle_t alloc_handle(struct kobject *kobj, right_t right)
{
	return __alloc_handle(current_proc, kobj, right);
}

int setup_handle(handle_t handle, struct kobject *kobj, right_t right)
{
	struct process *proc = current_proc;
	struct handle_desc *hd;
	struct handle_table_desc *htd;
	int ret;

	ASSERT(!WRONG_HANDLE(handle));

	spin_lock(&proc->kobj_lock);
	ret = lookup_handle_desc(proc, handle, &hd, &htd);
	if (ret)
		goto out;

	ASSERT(hd->kobj != NULL);
	hd->kobj = kobj;
	hd->right = right;
out:
	spin_unlock(&proc->kobj_lock);
	return ret;
}

handle_t send_handle(struct process *proc, struct process *pdst,
		handle_t handle, right_t right_send)
{
	struct handle_table_desc *htd;
	struct handle_desc *hdesc;
	struct kobject *kobj;
	int right;
	int ret;

	if (WRONG_HANDLE(handle))
		return -EINVAL;

	spin_lock(&proc->kobj_lock);
	ret = lookup_handle_desc(proc, handle, &hdesc, &htd);
	if (ret)
		goto out;

	kobj = hdesc->kobj;
	right = hdesc->right;
	if (!kobj || (kobj == KOBJ_PLACEHOLDER) || !right) {
		ret = -EPERM;
		goto out;
	}

	/*
	 * if the current process has the grant right of this kobject
	 * it can send any right which this kobject has, the GRANT
	 * right only can be get when create the kobject.
	 *
	 * otherwise it can only send the right which the process
	 * has to other process.
	 */
	if (right & KOBJ_RIGHT_GRANT) {
		right_send &= (KOBJ_RIGHT_MASK & kobj->right);
	} else {
		if ((right_send & (~right)) != 0) {
			ret = -EPERM;
			goto out;
		}
	}

	ret =  __alloc_handle(pdst, kobj, right_send);
	if (ret > 0)
		hdesc->right = KOBJ_RIGHT_NONE;
out:
	spin_unlock(&proc->kobj_lock);

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

int get_kobject_from_process(struct process *proc, handle_t handle,
			struct kobject **kobj, right_t *right)
{
	int ret;
	struct kobject *tmp;
	struct handle_desc *hd;
	struct handle_table_desc *htd;

	if (WRONG_HANDLE(handle) || !proc)
		return -ENOENT;

	spin_lock(&proc->kobj_lock);
	ret = lookup_handle_desc(proc, handle, &hd, &htd);
	if (ret)
		goto out;

	tmp = hd->kobj;

	if ((tmp != NULL) && (tmp != KOBJ_PLACEHOLDER)) {
		if (kobject_get(tmp)) {
			*kobj = tmp;
			*right = hd->right;
			ret = 0;
		}
	}
out:
	spin_unlock(&proc->kobj_lock);
	return ret;
}

int get_kobject(handle_t handle, struct kobject **kobj, right_t *right)
{
	return get_kobject_from_process(current_proc, handle, kobj, right);
}

int put_kobject(struct kobject *kobj)
{
	return kobject_put(kobj);
}

void process_handles_deinit(struct process *proc)
{
	struct handle_desc *table = proc->handle_desc_table;
	struct handle_table_desc *tdesc = to_handle_table_desc(table);
	struct handle_desc *tmp;

	while (table != NULL) {
		tmp = tdesc->next;
		tdesc = to_handle_table_desc(tmp);
		free_pages(table);
		table = tmp;
	}
}

static void release_handle_table(struct handle_desc *table)
{
	struct handle_desc *hdesc = table;
	int i;

	for (i = 0; i < NR_DESC_PER_PAGE; i++) {
		if ((hdesc->kobj) && (hdesc->kobj != KOBJ_PLACEHOLDER))
			kobject_close(hdesc->kobj, hdesc->right);
		hdesc++;
	}
}

void release_proc_kobjects(struct process *proc)
{
	struct handle_desc *table = proc->handle_desc_table;
	struct handle_table_desc *tdesc = to_handle_table_desc(table);
	struct handle_desc *tmp;

	while (table != NULL) {
		tmp = tdesc->next;
		tdesc = to_handle_table_desc(tmp);
		release_handle_table(table);
		table = tmp;
	}
}

int init_proc_handles(struct process *proc)
{
	extern struct kobject stdio_kobj;
	handle_t handle;

	spin_lock_init(&proc->kobj_lock);
	proc->handle_desc_table = new_handle_desc_table(0);
	if (!proc->handle_desc_table)
		return -ENOMEM;

	/*
	 * process kobj is 0, process can use this handle
	 * to control itself.
	 *
	 * stdout stdin and stderr will provided by kernel, for process
	 * handle [1] is stdout
	 * handle [2] is stdin
	 * handle [3] is stderr
	 */
	handle = __alloc_handle(proc, &proc->kobj, KOBJ_RIGHT_RW | KOBJ_RIGHT_CTL);
	ASSERT(handle == 0);
	handle = __alloc_handle(proc, &stdio_kobj, KOBJ_RIGHT_READ);
	ASSERT(handle == 1);
	handle = __alloc_handle(proc, &stdio_kobj, KOBJ_RIGHT_WRITE);
	ASSERT(handle == 2);
	handle = __alloc_handle(proc, &stdio_kobj, KOBJ_RIGHT_WRITE);
	ASSERT(handle == 3);

	return 0;
}
